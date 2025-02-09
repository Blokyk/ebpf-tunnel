package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Extract inode from a symbolic link pointing to the socket (simplified)
func extractInodeFromLink(link string) (int, error) {
	// In a real implementation, you would parse the link to get the inode
	// This is a simplified mock that assumes it always returns a specific inode
	// You'd need to parse the link string like "socket:[12345]" to extract the inode
	if strings.Contains(link, "socket:") {
		// Mock inode value extraction, assuming "socket:[12345]" -> inode 12345
		inodeStr := strings.TrimPrefix(link, "socket:[")
		inodeStr = strings.TrimSuffix(inodeStr, "]")
		return strconv.Atoi(inodeStr)
	}
	return 0, fmt.Errorf("invalid socket link format")
}

// Function to get the PID from the inode of a socket
func getPidFromInode(inode int) (int, error) {
	// Open /proc directory
	procDir := "/proc"
	files, err := os.ReadDir(procDir)
	if err != nil {
		return -1, err
	}

	// Iterate through all process directories in /proc
	for _, file := range files {
		// Skip non-process directories
		if _, err := strconv.Atoi(file.Name()); err != nil {
			continue
		}

		// Construct path to the /proc/[pid]/fd directory
		fdDir := filepath.Join(procDir, file.Name(), "fd")
		fdFiles, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		// Check each file descriptor in /proc/[pid]/fd/
		for _, fdFile := range fdFiles {
			fdPath := filepath.Join(fdDir, fdFile.Name())

			// Read the symbolic link to check the socket's inode
			link, err := os.Readlink(fdPath)
			if err != nil {
				continue
			}

			// If the link points to a socket, extract the inode (simplified)
			socketInode, err := extractInodeFromLink(link)
			if err != nil {
				continue
			}

			// If the inode matches, return the PID
			if socketInode == inode {
				pid, _ := strconv.Atoi(file.Name())
				return pid, nil
			}
		}
	}

	return -1, fmt.Errorf("no process found for inode %d", inode)
}

func getPidFromPort(proxyPort uint16) (uint64, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		log.Fatalf("Couldn't open /proc/net/tcp: %v", err)
		return 0, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// skip first line, which is just headers
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// the second field in /proc/net/tcp is the local addr, with the
		// fixed format XXXXXXXX:XXXX, in hexadecimal, and in network byte-order
		//           ip ^~~~~~~^ ^~~^ port
		// we only care about the port, though ip should always be 0100007F (127.0.0.1)
		localAddr := fields[1]
		portStr := localAddr[9:]
		port, err := strconv.ParseUint(portStr, 16, 16)

		if err != nil {
			log.Printf("WARN: Couldn't parse port number from '%s'", portStr)
			continue
		}

		if uint16(port) != proxyPort {
			continue
		}

		inode, err := strconv.Atoi(fields[9])
		if err != nil {
			log.Fatalf(
				"Found /proc/net/tcp entry with real proxy's port (%d) but couldn't read its inode (got '%s'): %v",
				proxyPort, fields[9], err,
			)
		}

		proxyPid, err := getPidFromInode(inode)
		if err != nil {
			log.Fatalf("Got inode for real proxy, but couldn't find its PID: %v", err)
		}

		return uint64(proxyPid), nil
	}

	return 0, fmt.Errorf("couldn't find any process listening on port %d", proxyPort)
}
