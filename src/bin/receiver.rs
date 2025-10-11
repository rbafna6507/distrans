use core::error;
use std::error::Error;
use tokio::net::TcpSocket;
use std::time::Duration;
use std::net::{SocketAddr};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt};

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

        // If either operation errors, the select will end.
        // A more robust implementation would handle these errors.
        _ = tokio::time::sleep(Duration::from_millis(50)) => {
            stream = stream;
        }
    };


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


async fn attempt_p2p_connection(local_addr: SocketAddr, receiver_addr: SocketAddr) -> Result<TcpStream, Box<dyn Error>> {
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
            return Ok(p2p_stream);
        }

        // Try to connect to the peer
        Ok(p2p_stream) = connect_socket.connect(receiver_addr) => {
            println!("SUCCESS: Connected to peer!");
            return Ok(p2p_stream);
        }

        // If either operation errors, the select will end.
        // A more robust implementation would handle these errors.
        _ = tokio::time::sleep(Duration::from_millis(50)) => {
            return Err("Could not create P2P connection".into())
        }
    };
    Err("Could not create P2P connection".into())
}


async fn establish_connection(relay_addr: &str) -> Result<TcpStream, Box<dyn Error>> {
    // Connect to relay server
    let mut relay_stream = TcpStream::connect(relay_addr).await?;
    println!("Connected to relay server at {}", relay_addr);

    // Get receiver address from relay
    let mut buffer = vec![0; 1024];
    let receiver_addr = match relay_stream.read(&mut buffer).await {
        Ok(0) => return Err("Relay server closed connection".into()),
        Ok(n) => {
            let addr: SocketAddr = serde_json::from_slice(&buffer[..n])?;
            println!("Received peer address: {}", addr);
            addr
        }
        Err(e) => return Err(e.into()),
    };

    let local_addr = relay_stream.local_addr()?;

    // Try P2P first with multiple attempts
    for attempt in 1..=3 {
        println!("P2P attempt {} of 3", attempt);
        
        match attempt_p2p_connection(local_addr, receiver_addr).await {
            Ok(p2p_stream) => {
                println!("P2P connection established, closing relay");
                // Optionally notify relay that P2P succeeded
                return Ok(p2p_stream);
            }
            Err(e) => {
                println!("P2P attempt {} failed: {}", attempt, e);
                if attempt < 3 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    // Fall back to relay
    println!("P2P failed, using relay connection");
    Ok(relay_stream)
}