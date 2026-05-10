# --- THE ADDRESS ---
# "0.0.0.0" is a special code that means "listen on every available network interface."
# If your computer has Wi-Fi and an Ethernet cable, it will listen for connections 
# coming from both. It makes the server accessible to other devices on your network.
HOST = "0.0.0.0"

# --- THE DOOR NUMBER ---
# Think of the IP (HOST) as the street address and the PORT as the specific apartment number.
# Data sent to your computer needs to know which "door" (app) to go to. 
# 2222 is a custom port number often used for testing or SSH-like services.
PORT = 2222

# --- THE CAPACITY ---
# This is the "Maximum Occupancy" sign for your server.
# It limits the number of people (clients) who can be connected at the exact same time.
# If connection #101 tries to join, the server will usually ignore or reject them.
MAX_CONNECTIONS = 100

# --- THE PATIENCE TIMER ---
# This defines how many seconds the server will wait for a client to send data.
# If a user connects but stays silent for more than 60 seconds, the server 
# will "hang up" (close the connection) to save resources.
READ_TIMEOUT = 60