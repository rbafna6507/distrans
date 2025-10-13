use tokio::net::{TcpStream, TcpSocket, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::{error::Error, net::SocketAddr};
use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Init{
    pub is_sender: bool,
    pub room: u32
    // other relevant file data eventually
    // like pake password hash
    // file metadata - name, size, etc
}


pub fn create_reusable_socket(local_addr: SocketAddr) -> Result<TcpSocket, Box<dyn Error>> {
    let listen_socket = match local_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    listen_socket.set_reuseaddr(true)?;
    listen_socket.set_reuseport(true)?;
    listen_socket.bind(local_addr)?;
    
    Ok(listen_socket)
}


pub async fn attempt_p2p_connection(local_addr: SocketAddr, receiver_addr: SocketAddr) -> Result<TcpStream, Box<dyn Error>> {
    // open a listening socket to accept the tcp hole punch
    let listen_socket: TcpSocket = create_reusable_socket(local_addr)?;
    let listener: TcpListener = listen_socket.listen(1024)?;
    println!("Listener is ready on {}", local_addr);

    // open a new socket connection to connect to the other peer
    let connect_socket:TcpSocket = create_reusable_socket(local_addr)?;
    println!("Connector is ready on {}", local_addr);

    tokio::select! {
        // try to accept peer's connection
        Ok((p2p_stream, _addr)) = listener.accept() => {
            println!("SUCCESS: Accepted peer connection!");
            return Ok(p2p_stream);
        }

        // try connecting to peer (tcp hole punch) 
        Ok(p2p_stream) = connect_socket.connect(receiver_addr) => {
            println!("SUCCESS: Connected to peer!");
            return Ok(p2p_stream);
        }

        // timeout after 50ms, keep the relay stream
        _ = tokio::time::sleep(Duration::from_millis(50)) => {
            return Err("Could not create P2P connection".into())
        }
    };
}


pub async fn establish_connection(relay_addr: &str, init: Init) -> Result<TcpStream, Box<dyn Error>> {
    // connect to relay server
    let mut relay_stream: TcpStream = TcpStream::connect(relay_addr).await?;
    println!("Connected to relay server at {}", relay_addr);

    let encoded_init: Vec<u8> = bincode::serialize(&init).unwrap();
    relay_stream.write_all(&encoded_init).await?;

    // get the peer's ip:port
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

    // keep track of the current local address we connected to the relay with
    let local_addr = relay_stream.local_addr()?;

    // three attempts at connecting to the peer directly
    for attempt in 1..=3 {
        println!("P2P attempt {} of 3", attempt);
        
        match attempt_p2p_connection(local_addr, receiver_addr).await {
            Ok(p2p_stream) => {
                println!("P2P connection established, closing relay");
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

    // if p2p failed, fallback to relay
    println!("P2P failed, using relay connection");
    Ok(relay_stream)
}