const { exec } = require('child_process')

// 1. hardhat nodeを起動し、ACCをデプロイ
// 2. cargo run --release -- --listen-address /ip4/127.0.0.1/tcp/40837 --group 0 provide
// 3. node set_provider.js
async function main() {
    let nodeEndpoints = ["/ip4/127.0.0.1/tcp/40837/p2p/12D3KooWCxnyz1JxC9y1RniRQVFe2cLaLHsYNc2SnXbM7yq5JBbJ"];
    let port = 40838;

    //console.log('cargo run -- --listen-address /ip4/127.0.0.1/tcp/40837 --secret-key-seed 1 provide');
    /*
    exec('cargo run -- --listen-address /ip4/127.0.0.1/tcp/40837 --secret-key-seed 1 provide', (err, stdout, stderr) => {
            if (err) {
                console.log(`stderr: ${stderr}`)
                return
            }
            console.log(`stdout: ${stdout}`)
        }
    )*/

    for (let i = 0; i < 40; i++) {

        if(i === 0) continue;
        let command = `cargo run --release -- --peer ${nodeEndpoints[0]} --listen-address /ip4/127.0.0.1/tcp/${port} --group ${i} provide`;

        console.log(command);
        exec(command, (err, stdout, stderr) => {
                if (err) {
                    console.log(`stderr: ${stderr}`)
                    return
                }
                console.log(`stdout: ${stdout}`)
            }
        )

        port += 1;
    }


}

main();