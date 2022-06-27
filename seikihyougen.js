let s = 'hoge Local node is listening on "/ip4/127.0.0.1/tcp/40838/p2p/12D3KooWH3uVF6wv47WnArKHk5p6cvgCJEb74UTmxztmQDc298L3"'
let x = s.match(/Local node is listening on \".*\"/);

let substr = x[0].substr(28);
let endpoint = substr.substr(0, substr.length-1);
console.log(endpoint);
