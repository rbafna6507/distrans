use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use distrans::networking::{establish_connection};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to the server
    // 100.86.70.21:8443 for relay pi
    let addr = "127.0.0.1:3000";
    let mut stream = establish_connection(addr).await?;

    // note: need to do PAKE shit here

    // loop where we continually recieve data + send acks/verification messages
    // note: maybe spawn this as an async tokio task? any benefit to doing that on the reciever?
    loop {

        let mut buffer = vec![0; 1024];
        println!("back here");
        // Read the server's echo
        match stream.read(&mut buffer).await {
            Ok(0) => {
                // Connection closed by the server
                println!("Server closed the connection.");
                break;
            },
            Ok(n) => {
                let received = String::from_utf8_lossy(&buffer[..n]);
                println!("Received echo: '{}'", received);

                // echo back
                let echo_string = String::from("Echo: ") + &received.to_string();
                if let Err(e) = stream.write_all(echo_string.as_bytes()).await {
                    break;
                }
            },
            Err(e) => {
                eprintln!("Failed to read from server: {}", e);
                break;
            }
        }
    }

    println!("Disconnecting.");
    Ok(())
}