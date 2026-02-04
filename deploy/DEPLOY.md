# Deployment Guide

## Release Process

### 1. Create a GitHub Release

Tag a new version to trigger automated builds:

```bash
git tag v0.1.0
git push origin v0.1.0
```

This triggers `.github/workflows/release.yml` which:
- Builds desktop apps for macOS (ARM + Intel), Linux, Windows
- Creates a GitHub Release with all binaries

### 2. Deploy to drista.paraxiom.org

SSH into Alice (the main server):

```bash
ssh -i ~/.ssh/ovh_simple ubuntu@51.79.26.123
```

#### Deploy install.sh

```bash
# On Alice
sudo cp /path/to/install.sh /var/www/drista/install.sh
sudo chmod 644 /var/www/drista/install.sh
```

#### Deploy downloads page

```bash
# On Alice
sudo cp /path/to/downloads.html /var/www/drista/downloads.html
```

#### Update nginx (if needed)

Add route for downloads page in `/etc/nginx/sites-available/drista`:

```nginx
location = /downloads {
    alias /var/www/drista/downloads.html;
}

location = /install.sh {
    alias /var/www/drista/install.sh;
    default_type text/plain;
}
```

Then reload:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 3. Quick Deploy Script

Run from your local machine:

```bash
# Deploy files to Alice
scp -i ~/.ssh/ovh_simple deploy/scripts/install.sh ubuntu@51.79.26.123:/tmp/
scp -i ~/.ssh/ovh_simple deploy/downloads.html ubuntu@51.79.26.123:/tmp/

# SSH and move to correct location
ssh -i ~/.ssh/ovh_simple ubuntu@51.79.26.123 << 'EOF'
sudo cp /tmp/install.sh /var/www/drista/
sudo cp /tmp/downloads.html /var/www/drista/
sudo chmod 644 /var/www/drista/install.sh /var/www/drista/downloads.html
echo "Deployed successfully!"
EOF
```

## URLs After Deployment

- **Web App**: https://drista.paraxiom.org
- **Downloads**: https://drista.paraxiom.org/downloads
- **Install Script**: https://drista.paraxiom.org/install.sh
- **GitHub Releases**: https://github.com/Paraxiom/drista/releases

## Verify Deployment

```bash
# Check install.sh is served correctly
curl -I https://drista.paraxiom.org/install.sh

# Check downloads page
curl -I https://drista.paraxiom.org/downloads
```
