use std::error::Error;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Connect to the server
    let mut stream = TcpStream::connect("127.0.0.1:8080").await?;
    println!("Successfully connected to server at 127.0.0.1:8080");

    loop {

        let mut input = String::new();
        let mut buffer = vec![0; 1024];

        println!("Enter a message to send:");
        std::io::stdin().read_line(&mut input)?;

        let message = input.trim();

        if message == "exit" {
            break;
        }

        // Write the message to the stream
        stream.write_all(message.as_bytes()).await?;
        println!("Sent: '{}'", message);

        // Read the server's echo
        match stream.read(&mut buffer).await {
            Ok(0) => {
                // Connection closed by the server
                println!("Server closed the connection.");
            },
            Ok(n) => {
                let received = String::from_utf8_lossy(&buffer[..n]);
                println!("Received echo: '{}'", received);
            },
            Err(e) => {
                eprintln!("Failed to read from server: {}", e);
            }
        }
    }

    println!("Disconnecting.");
    Ok(())
}

