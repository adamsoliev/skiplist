# Claude Code Notes

## CI Testing with Multipass

Always test CI changes locally in an Ubuntu VM using multipass before pushing:

```bash
# Create VM
multipass launch --name ci-test --memory 2G --disk 10G

# Mount project
multipass mount /Users/adamsoliev/Development/mini-lsm ci-test:/home/ubuntu/mini-lsm

# Run tests inside VM
multipass exec ci-test -- bash -c "cd /home/ubuntu/mini-lsm && <command>"
```
