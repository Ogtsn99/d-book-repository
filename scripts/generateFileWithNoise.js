const fs = require("fs");

let N = parseInt(process.argv[2]);
console.log(N);

function getRandomInt(max) {
    return Math.floor(Math.random() * max);
}

let u8Array = new Uint8Array(N);

for (let i = 0; i < N; i++) {
    u8Array[i] = getRandomInt(256);
}

console.log(Buffer.from(u8Array));
fs.writeFile(N.toString()+"Sample", Buffer.from(u8Array), (err) => {
    if (err) throw err;
    console.log('正常に書き込みが完了しました');
});
