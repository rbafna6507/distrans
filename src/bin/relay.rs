use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::error::Error;
use std::os::unix::net::SocketAddr;


// probably do need a class to manage all the connections
// 
struct Connection {
    stream: TcpStream,
    addr: SocketAddr
}

struct ConnectionManager {
    sender: Connection,
    receiver: Connection,
    connections: u32

    // need channels for both sender and receiver????
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Server listening on 127.0.0.1:8080");
    let mut connections:u32 = 0;

    loop {
        let (mut stream, addr) = listener.accept().await?;
        connections += 1;
        println!("New connection from: {}", addr);

        tokio::spawn(async move {
            let mut buffer = vec![0; 1024];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => { // Connection closed
                        println!("Client {} disconnected.", addr);
                        break;
                    },
                    Ok(n) => {
                        let sender_message = String::from_utf8_lossy(&buffer[..n]);
                        println!("Received from {}: {}", addr, sender_message);

                        // send message from sender to receier

                        // Echo back the message
                        if let Err(e) = stream.write_all(&buffer[..n]).await {
                            eprintln!("Failed to write to client {}: {}", addr, e);
                            break;
                        }
                    },
                    Err(e) => {
                        eprintln!("Error reading from client {}: {}", addr, e);
                        break;
                    }
                }
            }
        });
    }

}
