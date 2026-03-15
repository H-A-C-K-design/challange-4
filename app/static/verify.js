// v1.0 - integrity check module
// DO NOT MODIFY

(function(_0x4a1b,_0x3c2d){
  var _0x1f=function(_0x5e,_0x6f){return _0x5e+_0x6f;};
  // encoded endpoint reference: base64("/api/verify") = L2FwaS92ZXJpZnk=
  var _ep=atob("L2FwaS92ZXJpZnk=");

  // XOR verification stub - mirrors server-side checker logic
  // key derivation: k = input.length (count your steps)
  window._verify=function(flag){
    var k=flag.length;
    var enc=[];
    for(var i=0;i<flag.length;i++){
      enc.push(flag.charCodeAt(i)^(k%256));
    }
    return fetch(_ep,{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({flag:flag})
    }).then(function(r){return r.json();});
  };

  // Obfuscated hint: the number of characters in the flag is the XOR key
  // atob("Y291bnQgeW91ciBzdGVwcw==") => "count your steps"
  var _h=atob("Y291bnQgeW91ciBzdGVwcw==");
  console.debug(_0x1f("// hint: ",_h));
})();
