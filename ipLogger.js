const fs = require('fs').promises;
const path = require('path');

class IPLogger {
    constructor() {
        this.logsDir = path.join(__dirname, 'logs');
        this.ensureLogsDir();
    }

    async ensureLogsDir() {
        try {
            await fs.access(this.logsDir);
        } catch (error) {
            await fs.mkdir(this.logsDir, { recursive: true });
        }
    }

    /**
     * Log an IP address for a user
     * @param {string} userId - The user ID
     * @param {string} username - The username
     * @param {string} ipAddress - The IP address to log
     * @param {string} action - The action being performed (login, admin_access, etc.)
     */
    async logIP(userId, username, ipAddress, action = 'access') {
        try {
            const timestamp = new Date().toISOString();
            const logEntry = {
                timestamp,
                userId,
                username,
                ipAddress,
                action
            };

            // Create user-specific log file
            const userLogFile = path.join(this.logsDir, `user_${userId}_ips.json`);
            
            let existingLogs = [];
            try {
                const fileContent = await fs.readFile(userLogFile, 'utf8');
                existingLogs = JSON.parse(fileContent);
            } catch (error) {
                // File doesn't exist or is empty, start with empty array
                existingLogs = [];
            }

            // Add new log entry
            existingLogs.push(logEntry);

            // Keep only the last 50 IP logs per user to prevent files from growing too large
            if (existingLogs.length > 50) {
                existingLogs = existingLogs.slice(-50);
            }

            // Write back to file
            await fs.writeFile(userLogFile, JSON.stringify(existingLogs, null, 2));

            // Also log to a general IP log file for admin monitoring
            await this.logToGeneralFile(logEntry);

        } catch (error) {
            console.error('Error logging IP:', error);
        }
    }

    /**
     * Log to general IP log file for admin monitoring
     * @param {object} logEntry - The log entry object
     */
    async logToGeneralFile(logEntry) {
        try {
            const generalLogFile = path.join(this.logsDir, 'all_ips.json');
            
            let existingLogs = [];
            try {
                const fileContent = await fs.readFile(generalLogFile, 'utf8');
                existingLogs = JSON.parse(fileContent);
            } catch (error) {
                existingLogs = [];
            }

            existingLogs.push(logEntry);

            // Keep only the last 1000 entries in general log
            if (existingLogs.length > 1000) {
                existingLogs = existingLogs.slice(-1000);
            }

            await fs.writeFile(generalLogFile, JSON.stringify(existingLogs, null, 2));
        } catch (error) {
            console.error('Error logging to general IP file:', error);
        }
    }

    /**
     * Get IP addresses for a specific user
     * @param {string} userId - The user ID
     * @returns {Array} Array of IP log entries
     */
    async getUserIPs(userId) {
        try {
            const userLogFile = path.join(this.logsDir, `user_${userId}_ips.json`);
            const fileContent = await fs.readFile(userLogFile, 'utf8');
            const logs = JSON.parse(fileContent);
            
            // Return unique IPs with their latest access time
            const ipMap = new Map();
            
            logs.forEach(log => {
                if (!ipMap.has(log.ipAddress) || new Date(log.timestamp) > new Date(ipMap.get(log.ipAddress).timestamp)) {
                    ipMap.set(log.ipAddress, log);
                }
            });

            return Array.from(ipMap.values()).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        } catch (error) {
            console.error('Error reading user IPs:', error);
            return [];
        }
    }

    /**
     * Get the most recent IP address for a user
     * @param {string} userId - The user ID
     * @returns {string|null} The most recent IP address or null if none found
     */
    async getUserLatestIP(userId) {
        try {
            const userIPs = await this.getUserIPs(userId);
            return userIPs.length > 0 ? userIPs[0].ipAddress : null;
        } catch (error) {
            console.error('Error getting user latest IP:', error);
            return null;
        }
    }

    /**
     * Get all IP logs for admin monitoring
     * @param {number} limit - Maximum number of entries to return
     * @returns {Array} Array of all IP log entries
     */
    async getAllIPLogs(limit = 100) {
        try {
            const generalLogFile = path.join(this.logsDir, 'all_ips.json');
            const fileContent = await fs.readFile(generalLogFile, 'utf8');
            const logs = JSON.parse(fileContent);
            
            return logs.slice(-limit).reverse(); // Return most recent first
        } catch (error) {
            console.error('Error reading all IP logs:', error);
            return [];
        }
    }

    /**
     * Clean up old log files (optional maintenance function)
     * @param {number} daysOld - Remove files older than this many days
     */
    async cleanupOldLogs(daysOld = 30) {
        try {
            const files = await fs.readdir(this.logsDir);
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - daysOld);

            for (const file of files) {
                const filePath = path.join(this.logsDir, file);
                const stats = await fs.stat(filePath);
                
                if (stats.mtime < cutoffDate && file.startsWith('user_') && file.endsWith('_ips.json')) {
                    await fs.unlink(filePath);
                    console.log(`Cleaned up old IP log file: ${file}`);
                }
            }
        } catch (error) {
            console.error('Error cleaning up old logs:', error);
        }
    }
}

module.exports = new IPLogger();