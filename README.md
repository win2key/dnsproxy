# DNSProxy

`dnsproxy` is a tool designed to simplify the lives of developers who need to switch between different environments (local, development, production) for their websites. Instead of manually editing hosts files to see how a site looks across different stages, `dnsproxy` allows you to quickly switch DNS configurations with the click of a button.

## Features

- **Environment Switching**: Easily switch between local, development, production, and world environments.
- **Automatic DNS Configuration**: Automatically sets and resets DNS configurations on startup and exit.
- **Cross-Platform Support**: Works on macOS, Linux, and Windows.
- **Web Interface**: Simple web interface for switching environments.

## Requirements

- Administrative privileges (for setting DNS configurations)

## Installation

1. **Download the binary**:

   Go to the [Releases](https://github.com/win2key/dnsproxy/releases) page and download the appropriate binary for your operating system.

2. **Extract the binary**:

   Extract the downloaded archive to a directory of your choice.

3. **Create a `hosts.json` configuration file** in the same directory as the binary.

## Usage

1. **Run the program with administrative privileges**:

   - On macOS or Linux:
     ```sh
     sudo ./dnsproxy
     ```
   - On Windows:
     ```sh
     .\dnsproxy.exe
     ```

2. **Access the web interface**:

   Open a web browser and navigate to `http://localhost:5000`.

3. **Switch environments**:

   Use the provided buttons to switch between `local`, `dev`, `prod`, and `world` environments.

## Configuration

The `hosts.json` file should contain the environments and the sites you want to handle. Example structure:

```json
{
    "environment": {
        "local": "127.0.0.1",
        "dev": "1.2.3.4",
        "prod": "5.6.7.8",
        "world": ""
    },
    "sites": [
        "test.com",
        "example.com"
    ]
}
```

- **environment**: Maps environment names to IP addresses.
- **sites**: List of domain names you want to manage.

## How It Works

- **DNS Handling**: When a DNS query is received, the tool checks if the queried domain matches any site in the configuration. If it matches, it responds with the IP address of the current environment.
- **Environment Switching**: A web interface allows switching between environments by updating the current environment variable.
- **System DNS Management**: On startup, the tool sets the system's DNS to `127.0.0.1` and resets it to the original configuration on exit.

## Contributing

1. **Fork the repository**.
2. **Create a new branch** for your feature or bugfix.
3. **Submit a pull request** with a clear description of your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Support

For issues and feature requests, please visit the [GitHub Issues](https://github.com/win2key/dnsproxy/issues) page.

---



Happy coding! 🚀