use std::error::Error;
use std::vec;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use distrans::networking::{Init, establish_connection};
use distrans::bytes::{reconstruct_file};
use std::path::Path;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to the server
    // 100.86.70.21:8443 for relay pi
    let addr = "127.0.0.1:3000";

    let init:Init = Init {is_sender: false, room: 0};
    let mut stream: TcpStream = establish_connection(addr, init).await?;

    // note: need to do PAKE shit here - make the channel we communicte through secure

    // loop where we continually recieve data + send acks/verification messages
    // note: maybe spawn this as an async tokio task? any benefit to doing that on the reciever?
    let mut file: Vec<Vec<u8>> = Vec::new();
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
                println!("n: {}", n);
                println!("received {:?} from sender", buffer);
                buffer.truncate(n);
                file.push(buffer);

                // let received = String::from_utf8_lossy(&buffer[..n]);
                // println!("Received echo: '{}'", received);

                // // echo back
                // let echo_string = String::from("Echo: ") + &received.to_string();
                // if let Err(e) = stream.write_all(echo_string.as_bytes()).await {
                //     break;
                // }
            },
            Err(e) => {
                eprintln!("Failed to read from server: {}", e);
                break;
            }
        }
    }

    let output_path: &Path = Path::new("new_resume.pdf");
    reconstruct_file(file, output_path).await;

    println!("Disconnecting. Reconstructing file.");
    Ok(())
}