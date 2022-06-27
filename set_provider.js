const { exec } = require('child_process')

async function main() {
    let nodeEndpoints = ["/ip4/127.0.0.1/tcp/40837/p2p/12D3KooWPjceQrSwdWXPyLLeABRXmuqt69Rg3sBYbU1Nft9HyQ6X"];
    let port = 40838;

    console.log('cargo run -- --listen-address /ip4/127.0.0.1/tcp/40837 --secret-key-seed 1 provide');

    /*exec('cargo run -- --listen-address /ip4/127.0.0.1/tcp/40837 --secret-key-seed 1 provide', (err, stdout, stderr) => {
            if (err) {
                console.log(`stderr: ${stderr}`)
                return
            }
            console.log(`stdout: ${stdout}`)
        }
    )*/

    for (let i = 2; i <= 40; i++) {
        const _sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
        await _sleep(2000);

        let command = `cargo run -- --peer ${nodeEndpoints[0]} --listen-address /ip4/127.0.0.1/tcp/${port} --secret-key-seed ${i} provide`;

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


    console.log("yay");
}

main();