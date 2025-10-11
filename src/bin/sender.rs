use std::error::Error;
use std::net::{SocketAddr};
use std::time::Duration;
use tokio::net::{TcpStream, TcpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
struct Init{
    is_sender: bool,
    room: u32
    // other relevant file data eventually
    // like pake password hash
    // file metadata - name, size, etc
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    // Connect to the server
    // 100.86.70.21:8443 for relay pi
    let addr = "127.0.0.1:3000";
    let mut stream = TcpStream::connect(addr).await?;
    println!("Successfully connected to server at {}", addr);

    let mut buffer = vec![0; 1024];
    let receiver_addr:SocketAddr;

    // get sender's ip and port to connect to
    match stream.read(&mut buffer).await {
        Ok(0) => {
            // connection closed by server
            println!("Server closed the connection");
            return Ok(())
        },
        Ok(n) => {
            receiver_addr = serde_json::from_slice(&buffer[..n])?;
            println!("Received echo: '{}'", receiver_addr);
        },
        Err(e) => {
            eprintln!("Failed to read from server: {}", e);
            return Ok(())
        }
    }
    
    let local_addr = stream.local_addr()?;

    // open a listening socket to accept the tcp hole punchy
    let listen_socket = match local_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    listen_socket.set_reuseaddr(true)?;
    listen_socket.set_reuseport(true)?;
    listen_socket.bind(local_addr)?;
    let listener = listen_socket.listen(1024)?;
    println!("Listener is ready on {}", local_addr);

    // open a new socket connection to the 
    let connect_socket = match local_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    connect_socket.set_reuseaddr(true)?;
    connect_socket.set_reuseport(true)?;
    connect_socket.bind(local_addr)?;
    println!("Connector is ready on {}", local_addr);

    tokio::select! {
        // Try to accept the peer's connection
        Ok((p2p_stream, _addr)) = listener.accept() => {
            println!("SUCCESS: Accepted peer connection!");
            stream = p2p_stream;
        }

        // Try to connect to the peer
        Ok(p2p_stream) = connect_socket.connect(receiver_addr) => {
            println!("SUCCESS: Connected to peer!");
            stream = p2p_stream;
        }

        _ = tokio::time::sleep(Duration::from_millis(50)) => {
            stream = stream;
        }

        // If either operation errors, the select will end.
        // A more robust implementation would handle these errors.
    };

    loop {

        let mut input = String::new();
        let mut buffer = vec![0; 1024];

        println!("back here");

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
        // match stream.read(&mut buffer).await {
        //     Ok(0) => {
        //         // Connection closed by the server
        //         println!("Server closed the connection.");
        //     },
        //     Ok(n) => {
        //         let received = String::from_utf8_lossy(&buffer[..n]);
        //         println!("Received echo: '{}'", received);
        //     },
        //     Err(e) => {
        //         eprintln!("Failed to read from server: {}", e);
        //     }
        // }
    }

    println!("Disconnecting.");
    Ok(())
}

