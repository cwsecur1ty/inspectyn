import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { isPublicAddress, resolveTarget, pinnedRequestOptions, requestHeaders, collectTarget } from '../src/network.mjs';
import { normalizeTarget, validateConfig } from '../src/config.mjs';

test('scope rejects credentials, ambiguous addresses, ports, wildcards and query tokens', () => {
  for (const target of ['http://company.com','https://user:pass@company.com','https://company.com?token=secret',
    'https://company.com#token','https://company.com/?','https://company.com/#','https://company.com:8443','https://*.company.com','https://127.1','https://2130706433',
    'https://[::1]','https://localhost','https://company.com.','https://company.com\\@evil.com','https://company.com\n']) {
    assert.throws(()=>normalizeTarget(target),target);
  }
  assert.equal(normalizeTarget('https://COMPANY.com/path'),'https://company.com/path');
  assert.throws(()=>validateConfig({schemaVersion:1,targets:[]}));
  assert.throws(()=>validateConfig({schemaVersion:1,targets:['https://company.com'],followRedirects:true}));
  assert.throws(()=>validateConfig({schemaVersion:1,targets:['https://company.com'],timeoutMs:0}));
});

test('public-address boundary rejects private, special-use and encoded IPv6 routes', () => {
  for (const address of ['0.0.0.0','10.2.3.4','100.64.1.1','127.0.0.1','169.254.169.254','172.31.4.5','192.168.1.1',
    '192.0.0.9','192.0.2.1','198.18.0.1','198.51.100.2','203.0.113.2','224.0.0.1','255.255.255.255',
    '::1','::ffff:127.0.0.1','::ffff:8.8.8.8','fc00::1','fe80::1','64:ff9b::a00:1','2001:db8::1','2002:0808:0808::1','3fff::1','invalid']) {
    assert.equal(isPublicAddress(address),false,address);
  }
  for (const address of ['8.8.8.8','1.1.1.1','2606:4700:4700::1111']) assert.equal(isPublicAddress(address),true,address);
});

function resolver(overrides = {}) {
  return { resolve4: async()=>['8.8.8.8'],resolve6:async()=>[],resolveTxt:async()=>[],resolveMx:async()=>[],cancel(){},...overrides };
}

test('mixed public/private DNS answer is rejected before contact', async () => {
  await assert.rejects(resolveTarget('company.com',1000,true,resolver({resolve6:async()=>['::1']})),{code:'DESTINATION_BLOCKED'});
  await assert.rejects(resolveTarget('company.com',1000,false,resolver({resolve6:async()=>{throw Object.assign(Error(),{code:'ESERVFAIL'});}})),{code:'DNS_LOOKUP_FAILED'});
});

test('DNS failure is distinct from absent records and record count is bounded', async () => {
  const data = await resolveTarget('company.com',1000,true,resolver({resolveTxt:async()=>{throw Object.assign(Error(),{code:'ETIMEOUT'});}}));
  assert.equal(data.dns.spf.status,'error');
  assert.equal(data.dns.dmarc.status,'error');
  const empty = await resolveTarget('company.com',1000,true,resolver());
  assert.equal(empty.dns.spf.status,'absent');
  await assert.rejects(resolveTarget('company.com',1000,false,resolver({resolve4:async()=>Array(65).fill('8.8.8.8')})),{code:'DNS_LOOKUP_FAILED'});
});

test('request pins the actual IP while authenticating the original hostname', () => {
  const options = pinnedRequestOptions(new URL('https://company.com/path'),'8.8.8.8');
  assert.equal(options.hostname,'8.8.8.8');
  assert.equal(options.headers.Host,'company.com');
  assert.equal(options.headers['User-Agent'],'Inspectyn/0.2.0');
  assert.equal(options.servername,'company.com');
  assert.equal(options.agent,false);
  assert.equal(options.rejectUnauthorized,true);
  assert.equal(options.checkServerIdentity('8.8.8.8',{subjectaltname:'DNS:other.com'}).code,'ERR_TLS_CERT_ALTNAME_INVALID');
  assert.equal(options.checkServerIdentity('8.8.8.8',{subjectaltname:'DNS:company.com'}),undefined);
});

function mockRequest({address='8.8.8.8',authorized=true,status=302} = {}) {
  let requests = 0, closed = false;
  const request = (_options, callback) => {
    requests++;
    const req = new EventEmitter();
    req.destroy = ()=>{};
    req.end = () => queueMicrotask(()=>callback({ statusCode:status,headers:{location:'http://127.0.0.1/','set-cookie':'secret=abc','content-type':'text/html'},
      socket:{authorized,remoteAddress:address,getProtocol:()=> 'TLSv1.3',getPeerCertificate:()=>({valid_to:'Oct 20 12:00:00 2026 GMT'})},
      destroy(){closed=true;} }));
    return req;
  };
  return {request, stats:()=>({requests,closed})};
}

test('redirects are not followed; response bodies and sensitive headers are discarded', async () => {
  const mock = mockRequest();
  const result = await requestHeaders(new URL('https://company.com/'),'8.8.8.8',1000,mock.request);
  assert.equal(result.http.status,302);
  assert.deepEqual(result.http.headers,{'content-type':'text/html'});
  assert.deepEqual(mock.stats(),{requests:1,closed:true});
});

test('collector retains duplicate response header evidence that Node headers can discard', async () => {
  const request = (_options,callback) => {
    const req = Object.assign(new EventEmitter(),{destroy(){},end(){ queueMicrotask(()=>callback({
      statusCode:200,headers:{'content-type':'text/html'},headersDistinct:{'content-type':['text/html','application/json'],
        'strict-transport-security':['max-age=0','max-age=31536000'],'set-cookie':['secret=value']},
      socket:{authorized:true,remoteAddress:'8.8.8.8',getProtocol:()=> 'TLSv1.3',getPeerCertificate:()=>({valid_to:'Oct 20 12:00:00 2026 GMT'})},destroy(){}
    })); }});
    return req;
  };
  const result = await requestHeaders(new URL('https://company.com/'),'8.8.8.8',1000,request);
  assert.deepEqual(result.http.headers['content-type'],['text/html','application/json']);
  assert.deepEqual(result.http.headers['strict-transport-security'],['max-age=0','max-age=31536000']);
  assert.equal(result.http.headers['set-cookie'],undefined);
});

test('observed socket address and certificate authorization are checked', async () => {
  for (const setup of [{address:'127.0.0.1'},{authorized:false}]) {
    const mock = mockRequest(setup);
    await assert.rejects(requestHeaders(new URL('https://company.com/'),'8.8.8.8',1000,mock.request),{code:'TLS_DESTINATION_MISMATCH'});
    assert.equal(mock.stats().closed,true);
  }
});

test('header deadline destroys a stalled request', async () => {
  let destroyed = false;
  const request = () => Object.assign(new EventEmitter(),{end(){},destroy(){destroyed=true;}});
  await assert.rejects(requestHeaders(new URL('https://company.com/'),'8.8.8.8',10,request),{code:'ETIMEDOUT'});
  assert.equal(destroyed,true);
});

test('collector uses validated address and target only', async () => {
  let requested;
  const observed = await collectTarget('https://company.com/path',{dns:false,timeoutMs:1000},{
    resolveTarget:async(host,timeout,dns)=>{assert.deepEqual([host,timeout,dns],['company.com',1000,false]);return {address:'8.8.8.8'};},
    requestHeaders:async(url,address)=>{requested=[url.href,address];return {http:{status:200,headers:{}},tls:{authorized:true}};}
  });
  assert.deepEqual(requested,['https://company.com/path','8.8.8.8']);
  assert.equal(observed.hostname,'company.com');
});
