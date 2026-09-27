# Host Wembux

## Start the server

1. Install `Wembux-Download.exe` on the laptop that will host Wembux.
2. Run the desktop file `Start-Wembux-Server.bat`.
3. On first start, enter the owner username (the default is `FRIGSS_FINDER`) and choose a password. This creates the server-side owner account; browser-local accounts are not automatically imported.
4. The BAT prepares a Python environment and installs Cloudflare Tunnel with `winget` when needed. The console prints a temporary `https://...trycloudflare.com` link when the tunnel is ready.
5. Share that HTTPS link with users. They can register and use Wembux from their own devices while the host laptop stays awake and connected.

The temporary link changes when the tunnel restarts. For a stable address, configure a named Cloudflare Tunnel and your own domain. `Wembux-Status.bat` opens the local server status and account dashboard while the server is running.

## Data and security

SQLite data is stored in `%LOCALAPPDATA%\Wembux\data\wembux.sqlite3`. Stop the server before backing up that file. Passwords are stored as scrypt hashes and browser sessions use HTTP-only cookies. HTTPS protects traffic through the tunnel, but chat messages are not end-to-end encrypted and are stored on the host laptop. Do not use this prototype for sensitive conversations.

The laptop must remain online for friends to sign in and exchange messages. Press Ctrl+C in the server window to stop the service and tunnel.
