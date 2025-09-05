
#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Install pip
sudo apt update
sudo apt install python3-pip

# Install pipx using pip
echo "Installing pipx..."
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# Add pipx to PATH if not already present
if ! echo $PATH | grep -q "$HOME/.local/bin"; then
    echo "Adding pipx to PATH..."
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
    source ~/.bashrc
fi

# Install Poetry using pipx
echo "Installing Poetry..."
pipx install poetry

# Confirm installation
echo "Installation complete. Versions:"
pipx --version
poetry --version
