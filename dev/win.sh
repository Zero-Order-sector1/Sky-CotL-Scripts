#!/bin/bash
set -euo pipefail

# Constants
readonly CONFIG_FILE="docker-compose.yml"
readonly KEY_FILE=".enc.key"
readonly IV_FILE=".enc.iv"
readonly HASH_FILE=".enc.hash"
readonly MIN_PASSWORD_LENGTH=16

# Fungsi untuk cleanup
cleanup() {
    local files=("$CONFIG_FILE" "$CONFIG_FILE.enc" "$CONFIG_FILE.tmp")
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            shred -u -z -n 3 "$file"
        fi
    done
}

# Set trap untuk cleanup
trap cleanup EXIT INT TERM

# Fungsi untuk menghasilkan kunci enkripsi yang aman
generate_encryption_key() {
    openssl rand -hex 32 > "$KEY_FILE"  # 256-bit key in hex
    openssl rand -hex 16 > "$IV_FILE"   # 128-bit IV in hex
    chmod 600 "$KEY_FILE" "$IV_FILE"
}

# Fungsi untuk validasi hash
validate_file_hash() {
    local file="$1"
    local current_hash
    current_hash=$(sha256sum "$file" | cut -d' ' -f1)
    local stored_hash
    stored_hash=$(cat "$HASH_FILE" 2>/dev/null || echo "")
    
    [[ "$current_hash" == "$stored_hash" ]]
}

# Fungsi untuk menyimpan hash
store_file_hash() {
    local file="$1"
    sha256sum "$file" | cut -d' ' -f1 > "$HASH_FILE"
    chmod 600 "$HASH_FILE"
}

# Fungsi untuk memvalidasi password
validate_password() {
    local password="$1"
    if [[ ${#password} -lt $MIN_PASSWORD_LENGTH ]]; then
        echo "Error: Password harus minimal $MIN_PASSWORD_LENGTH karakter" >&2
        return 1
    fi
    if ! [[ "$password" =~ [A-Z] && "$password" =~ [a-z] && "$password" =~ [0-9] && "$password" =~ [^A-Za-z0-9] ]]; then
        echo "Error: Password harus mengandung huruf besar, huruf kecil, angka, dan karakter khusus" >&2
        return 1
    fi
    return 0
}

# Fungsi untuk mengenkripsi file dengan IV dan key yang aman
encrypt_file() {
    local file="$1"
    local encrypted_file="${file}.enc"
    local key iv

    if [[ ! -f "$KEY_FILE" ]] || [[ ! -f "$IV_FILE" ]]; then
        generate_encryption_key
    fi

    key=$(cat "$KEY_FILE")
    iv=$(cat "$IV_FILE")

    echo "Mengenkripsi file ${file}..."
    if ! openssl enc -aes-256-cbc -salt \
        -in "$file" \
        -out "$encrypted_file" \
        -pass "pass:${key}${iv}" \
        -pbkdf2 -iter 10000; then
        echo "Enkripsi gagal" >&2
        secure_delete "$encrypted_file"
        return 1
    fi

    store_file_hash "$encrypted_file"
    secure_delete "$file"
    echo "File berhasil dienkripsi: ${encrypted_file}"
}

# Fungsi untuk mendekripsi file
decrypt_file() {
    local encrypted_file="$1"
    local output_file="${encrypted_file%.enc}"
    local key iv

    if [[ ! -f "$KEY_FILE" ]] || [[ ! -f "$IV_FILE" ]]; then
        echo "Error: File kunci enkripsi tidak ditemukan" >&2
        return 1
    fi

    if ! validate_file_hash "$encrypted_file"; then
        echo "Error: File terenkripsi telah dimodifikasi" >&2
        return 1
    fi

    key=$(cat "$KEY_FILE")
    iv=$(cat "$IV_FILE")

    if ! openssl enc -aes-256-cbc -d -salt \
        -in "$encrypted_file" \
        -out "$output_file" \
        -pass "pass:${key}${iv}" \
        -pbkdf2 -iter 10000; then
        echo "Dekripsi gagal" >&2
        secure_delete "$output_file"
        return 1
    fi
}

# Fungsi untuk menghapus file secara aman
secure_delete() {
    local file="$1"
    if [[ -f "$file" ]]; then
        shred -u -z -n 3 "$file"
    fi
}

# Fungsi untuk memvalidasi URL
validate_url() {
    local url="$1"
    if ! [[ "$url" =~ ^https?:// ]]; then
        echo "Error: URL tidak valid. Harus dimulai dengan http:// atau https://" >&2
        return 1
    fi
    return 0
}

# Fungsi untuk menanyakan URL dengan validasi
prompt_version_url() {
    local url
    while true; do
        read -p "Masukkan URL Windows yang Anda inginkan: " url
        if validate_url "$url"; then
            echo "$url"
            break
        fi
    done
}

# Fungsi untuk memvalidasi dan menginstal dependensi
check_and_install_dependencies() {
    local dependencies=("docker" "docker-compose" "openssl" "shred")
    
    for dep in "${dependencies[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo "Menginstal $dep..."
            case "$dep" in
                "docker")
                    curl -fsSL https://get.docker.com -o get-docker.sh
                    sudo sh get-docker.sh
                    secure_delete get-docker.sh
                    ;;
                "docker-compose")
                    sudo curl -L "https://github.com/docker/compose/releases/download/$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep -Po '"tag_name": "\K.*?(?=")')/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
                    sudo chmod +x /usr/local/bin/docker-compose
                    ;;
                *)
                    sudo apt-get update && sudo apt-get install -y "$dep"
                    ;;
            esac
        fi
    done
}

# Fungsi untuk membuat password yang aman
generate_secure_password() {
    openssl rand -base64 16 | tr -dc 'a-zA-Z0-9!@#$%^&*()' | head -c 16
}

# Main execution
main() {
    # Check dan install dependencies
    check_and_install_dependencies

    # Generate kunci enkripsi jika belum ada
    if [[ ! -f "$KEY_FILE" ]]; then
        generate_encryption_key
    fi

    # Buat file docker-compose.yml
    echo "Membuat file konfigurasi Docker Compose..."
    version_url=$(prompt_version_url)
    secure_password=$(generate_secure_password)

    cat <<EOF > "$CONFIG_FILE"
version: '3.8'
services:
  windows:
    image: diana591/windows-master:v2.0
    container_name: windows
    environment:
      USERNAME: "secureuser"
      PASSWORD: "${secure_password}"
      DISK_SIZE: "92G"
      CPU_CORES: "4"
      RAM_SIZE: "11G"
      REGION: "en-US"
      KEYBOARD: "en-US"
      VERSION: "${version_url}"
      DOWNLOAD_TIMEOUT: "3600"  # 1 hour timeout for downloads
    volumes:
      - /winmoon:/storage
    devices:
      - /dev/kvm:/dev/kvm
    privileged: true  # Needed for proper KVM access
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
    security_opt:
      - no-new-privileges:true
    sysctls:
      - net.ipv4.ip_forward=1
      - net.ipv4.conf.all.promote_secondaries=1
    dns:
      - 8.8.8.8
      - 1.1.1.1
    ports:
      - "8006:8006"
      - "3389:3389/tcp"
      - "3389:3389/udp"
    networks:
      - windows_net
    stop_grace_period: 2m
    restart: always
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    mem_limit: 12G
    memswap_limit: 14G
    ulimits:
      nofile:
        soft: 65535
        hard: 65535
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "3389"]
      interval: 30s
      timeout: 10s
      retries: 3
networks:
  windows_net:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.20.0.0/16
EOF

    # Enkripsi file konfigurasi
    encrypt_file "$CONFIG_FILE"

    # Jalankan Docker Compose dengan retry mechanism
    echo "Menjalankan Docker Compose..."
    if [[ -f "${CONFIG_FILE}.enc" ]]; then
        decrypt_file "${CONFIG_FILE}.enc"
        if [[ -f "$CONFIG_FILE" ]]; then
            # Stop any existing container
            docker-compose down --remove-orphans 2>/dev/null || true
            
            # Clear Docker network
            docker network prune -f
            
            # Set network parameters
            sudo sysctl -w net.ipv4.ip_forward=1
            sudo sysctl -w net.core.rmem_max=2500000
            sudo sysctl -w net.core.wmem_max=2500000
            
            # Start with retry mechanism
            max_retries=3
            retry_count=0
            while [ $retry_count -lt $max_retries ]; do
                if docker-compose up -d; then
                    echo "Docker container started successfully"
                    break
                else
                    retry_count=$((retry_count + 1))
                    if [ $retry_count -lt $max_retries ]; then
                        echo "Retry $retry_count of $max_retries..."
                        sleep 10
                    else
                        echo "Failed to start Docker container after $max_retries attempts"
                        exit 1
                    fi
                fi
            done
            
            secure_delete "$CONFIG_FILE"
        else
            echo "Error: Gagal mendekripsi file konfigurasi" >&2
            exit 1
        fi
    else
        echo "Error: File konfigurasi terenkripsi tidak ditemukan" >&2
        exit 1
    fi

    echo "Layanan Docker berhasil dijalankan."
    echo "Password yang dihasilkan: $secure_password"
    echo "Simpan password ini di tempat yang aman!"

    # Timer Python yang lebih aman
    python3 - <<EOF
import datetime
import time
import signal
import sys

def signal_handler(sig, frame):
    print("\nTimer dihentikan.")
    sys.exit(0)

def print_elapsed_time():
    start_time = datetime.datetime.now()
    print("Timer dimulai. Tekan Ctrl+C untuk menghentikan.")
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        while True:
            current_time = datetime.datetime.now()
            elapsed_time = current_time - start_time
            seconds_elapsed = elapsed_time.total_seconds()
            
            print(f"Waktu berlalu: {int(seconds_elapsed)} detik", end="\r", flush=True)
            time.sleep(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    print_elapsed_time()
EOF
}

# Trap untuk membersihkan file sementara saat exit
trap 'secure_delete "$CONFIG_FILE" "${CONFIG_FILE}.enc"' EXIT

# Jalankan script
main
