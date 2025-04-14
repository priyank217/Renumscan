#official Kali Linux rolling image
FROM kalilinux/kali-rolling

# Update package lists and install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    sublist3r \
    assetfinder \
    httpx-toolkit \
    sslscan \
    whois \
    dnsrecon \
    naabu \
 && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app
COPY requirements.txt /app/

# Install required Python packages from requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy the rest of your project files into the container
COPY . /app
