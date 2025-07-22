echo "NUCLEUS_PORT=4000" >> .env
echo "NUCLEUS_SECRET=$(openssl rand -hex 36 | tr -d '\n')" >> .env
echo "COMMAND_HOSTNAME=localhost" >> .env
echo "COMMAND_PORT=3000" >> .env
echo "COMMAND_SECRET=$(openssl rand -hex 36 | tr -d '\n')" >> .env
echo "COMMAND_LISTEN_ADDR=0.0.0.0" >> .env
echo "POSTGRES_DB=forge" >> .env
echo "POSTGRES_USER=postgres" >> .env
echo "POSTGRES_PASSWORD=$(openssl rand -hex 36 | tr -d '\n')" >> .env
echo "POSTGRES_ENCRYPTION_KEY=$(openssl rand -hex 36 | tr -d '\n')" >> .env
# REPLACE with your VT API KEY
echo "VT_API_KEY=YOUR_VIRUS_TOTAL_API_KEY" >> .env
