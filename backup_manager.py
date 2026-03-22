"""
Backup and recovery manager for 3FA authentication system.
Provides automated backups and recovery procedures for user data and configurations.
"""

import os
import json
import shutil
import sqlite3
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import zipfile
import hashlib

logger = logging.getLogger(__name__)

class BackupManager:
    """Manages database backups and recovery operations."""

    def __init__(self, db_path: str, backup_dir: str = "backups"):
        self.db_path = db_path
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)

    def create_backup(self, backup_type: str = "full") -> str:
        """Create a backup of the database and configurations.

        Args:
            backup_type: Type of backup ('full', 'incremental', 'config_only')

        Returns:
            Path to the created backup file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"3fa_backup_{backup_type}_{timestamp}.zip"
        backup_path = self.backup_dir / backup_name

        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Backup database
                if backup_type in ['full', 'incremental']:
                    if os.path.exists(self.db_path):
                        zipf.write(self.db_path, f"database/{os.path.basename(self.db_path)}")
                        logger.info(f"Database backed up: {self.db_path}")

                # Backup configuration files
                config_files = [
                    'secret.key',
                    'biometric.key',
                    'config.py',
                    'requirements.txt'
                ]

                for config_file in config_files:
                    if os.path.exists(config_file):
                        zipf.write(config_file, f"config/{config_file}")

                # Backup templates and static files
                if backup_type == 'full':
                    for dir_name in ['templates', 'static']:
                        if os.path.exists(dir_name):
                            for root, dirs, files in os.walk(dir_name):
                                for file in files:
                                    file_path = os.path.join(root, file)
                                    arcname = os.path.join("web", os.path.relpath(file_path, "."))
                                    zipf.write(file_path, arcname)

                # Create backup metadata
                metadata = {
                    'backup_type': backup_type,
                    'timestamp': timestamp,
                    'version': '2.0.0',
                    'files': []
                }

                for file_info in zipf.filelist:
                    metadata['files'].append({
                        'filename': file_info.filename,
                        'size': file_info.file_size,
                        'compress_size': file_info.compress_size
                    })

                # Add metadata to backup
                zipf.writestr('backup_metadata.json', json.dumps(metadata, indent=2))

            # Calculate checksum
            with open(backup_path, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()

            checksum_file = backup_path.with_suffix('.sha256')
            with open(checksum_file, 'w') as f:
                f.write(f"{checksum}  {backup_name}\n")

            logger.info(f"Backup created successfully: {backup_path}")
            return str(backup_path)

        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            if backup_path.exists():
                backup_path.unlink()  # Remove failed backup
            raise

    def list_backups(self) -> List[Dict]:
        """List all available backups with metadata."""
        backups = []

        for backup_file in self.backup_dir.glob("*.zip"):
            checksum_file = backup_file.with_suffix('.sha256')

            try:
                # Read metadata from backup
                with zipfile.ZipFile(backup_file, 'r') as zipf:
                    if 'backup_metadata.json' in zipf.namelist():
                        metadata_content = zipf.read('backup_metadata.json')
                        metadata = json.loads(metadata_content)
                    else:
                        # Legacy backup without metadata
                        metadata = {
                            'backup_type': 'unknown',
                            'timestamp': backup_file.stat().st_mtime,
                            'version': 'unknown'
                        }

                # Verify checksum if available
                checksum_valid = False
                if checksum_file.exists():
                    with open(checksum_file, 'r') as f:
                        expected_checksum = f.read().split()[0]

                    with open(backup_file, 'rb') as f:
                        actual_checksum = hashlib.sha256(f.read()).hexdigest()

                    checksum_valid = expected_checksum == actual_checksum

                backups.append({
                    'filename': backup_file.name,
                    'path': str(backup_file),
                    'size': backup_file.stat().st_size,
                    'created': datetime.fromtimestamp(backup_file.stat().st_mtime),
                    'metadata': metadata,
                    'checksum_valid': checksum_valid
                })

            except Exception as e:
                logger.warning(f"Failed to read backup metadata for {backup_file}: {e}")
                backups.append({
                    'filename': backup_file.name,
                    'path': str(backup_file),
                    'size': backup_file.stat().st_size,
                    'created': datetime.fromtimestamp(backup_file.stat().st_mtime),
                    'metadata': None,
                    'checksum_valid': False
                })

        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        return backups

    def restore_backup(self, backup_path: str, restore_type: str = "full") -> bool:
        """Restore from a backup file.

        Args:
            backup_path: Path to the backup file
            restore_type: Type of restore ('full', 'database_only', 'config_only')

        Returns:
            True if restore was successful
        """
        backup_path = Path(backup_path)
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")

        # Verify checksum if available
        checksum_file = backup_path.with_suffix('.sha256')
        if checksum_file.exists():
            with open(checksum_file, 'r') as f:
                expected_checksum = f.read().split()[0]

            with open(backup_path, 'rb') as f:
                actual_checksum = hashlib.sha256(f.read()).hexdigest()

            if expected_checksum != actual_checksum:
                raise ValueError(f"Backup checksum verification failed for {backup_path}")

        try:
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                # Create restore directory
                restore_dir = Path("restore_temp")
                restore_dir.mkdir(exist_ok=True)

                try:
                    # Extract files based on restore type
                    for file_info in zipf.filelist:
                        if restore_type == "database_only" and not file_info.filename.startswith("database/"):
                            continue
                        elif restore_type == "config_only" and not file_info.filename.startswith("config/"):
                            continue

                        # Extract file
                        zipf.extract(file_info, restore_dir)

                    # Perform restore operations
                    if restore_type in ["full", "database_only"]:
                        # Restore database
                        db_backup = restore_dir / "database" / os.path.basename(self.db_path)
                        if db_backup.exists():
                            shutil.copy2(db_backup, self.db_path)
                            logger.info(f"Database restored from {db_backup}")

                    if restore_type in ["full", "config_only"]:
                        # Restore configuration files
                        config_dir = restore_dir / "config"
                        if config_dir.exists():
                            for config_file in config_dir.glob("*"):
                                shutil.copy2(config_file, ".")
                                logger.info(f"Config file restored: {config_file.name}")

                        # Restore web files
                        web_dir = restore_dir / "web"
                        if web_dir.exists():
                            for root, dirs, files in os.walk(web_dir):
                                for file in files:
                                    src = Path(root) / file
                                    dst = Path(".") / Path(root).relative_to(web_dir) / file
                                    dst.parent.mkdir(parents=True, exist_ok=True)
                                    shutil.copy2(src, dst)

                    logger.info(f"Restore completed successfully from {backup_path}")
                    return True

                finally:
                    # Clean up temporary files
                    shutil.rmtree(restore_dir, ignore_errors=True)

        except Exception as e:
            logger.error(f"Restore failed: {e}")
            raise

    def cleanup_old_backups(self, keep_days: int = 30, keep_count: int = 10):
        """Clean up old backup files.

        Args:
            keep_days: Keep backups newer than this many days
            keep_count: Keep at least this many recent backups
        """
        backups = self.list_backups()
        cutoff_date = datetime.now() - timedelta(days=keep_days)

        # Keep recent backups and those within the time window
        to_keep = []
        to_delete = []

        for backup in backups:
            if len(to_keep) < keep_count or backup['created'] > cutoff_date:
                to_keep.append(backup)
            else:
                to_delete.append(backup)

        # Delete old backups
        for backup in to_delete:
            try:
                Path(backup['path']).unlink()
                checksum_file = Path(backup['path']).with_suffix('.sha256')
                if checksum_file.exists():
                    checksum_file.unlink()
                logger.info(f"Deleted old backup: {backup['filename']}")
            except Exception as e:
                logger.warning(f"Failed to delete backup {backup['filename']}: {e}")

        logger.info(f"Cleanup completed. Kept {len(to_keep)} backups, deleted {len(to_delete)}")

    def get_backup_stats(self) -> Dict:
        """Get statistics about backups."""
        backups = self.list_backups()

        if not backups:
            return {
                'total_backups': 0,
                'total_size': 0,
                'oldest_backup': None,
                'newest_backup': None,
                'backup_types': {}
            }

        total_size = sum(b['size'] for b in backups)
        backup_types = {}
        for b in backups:
            btype = b.get('metadata', {}).get('backup_type', 'unknown')
            backup_types[btype] = backup_types.get(btype, 0) + 1

        return {
            'total_backups': len(backups),
            'total_size': total_size,
            'oldest_backup': min(b['created'] for b in backups),
            'newest_backup': max(b['created'] for b in backups),
            'backup_types': backup_types
        }


# Global backup manager instance
backup_manager = BackupManager("database/users.db")

def create_scheduled_backup(backup_type: str = "full") -> str:
    """Create a scheduled backup."""
    return backup_manager.create_backup(backup_type)

def restore_from_backup(backup_path: str, restore_type: str = "full") -> bool:
    """Restore from a backup file."""
    return backup_manager.restore_backup(backup_path, restore_type)

def get_backup_info() -> Dict:
    """Get backup statistics."""
    return backup_manager.get_backup_stats()

if __name__ == "__main__":
    # CLI interface for backup operations
    import sys

    if len(sys.argv) < 2:
        print("Usage: python backup_manager.py <command> [args...]")
        print("Commands:")
        print("  create [type]          - Create backup (type: full, incremental, config_only)")
        print("  list                   - List all backups")
        print("  restore <path> [type]  - Restore from backup")
        print("  cleanup [days] [count] - Clean up old backups")
        print("  stats                  - Show backup statistics")
        sys.exit(1)

    command = sys.argv[1]

    try:
        if command == "create":
            backup_type = sys.argv[2] if len(sys.argv) > 2 else "full"
            path = backup_manager.create_backup(backup_type)
            print(f"Backup created: {path}")

        elif command == "list":
            backups = backup_manager.list_backups()
            if not backups:
                print("No backups found.")
            else:
                print(f"{'Filename':<40} {'Size':<10} {'Created':<20} {'Type':<15} {'Valid'}")
                print("-" * 90)
                for b in backups:
                    size_mb = b['size'] / (1024 * 1024)
                    created = b['created'].strftime("%Y-%m-%d %H:%M:%S")
                    btype = b.get('metadata', {}).get('backup_type', 'unknown')
                    valid = "✓" if b['checksum_valid'] else "✗"
                    print(f"{b['filename']:<40} {size_mb:<10.1f}MB {created:<20} {btype:<15} {valid}")

        elif command == "restore":
            if len(sys.argv) < 3:
                print("Error: Please specify backup path")
                sys.exit(1)
            backup_path = sys.argv[2]
            restore_type = sys.argv[3] if len(sys.argv) > 3 else "full"
            success = backup_manager.restore_backup(backup_path, restore_type)
            print(f"Restore {'successful' if success else 'failed'}")

        elif command == "cleanup":
            keep_days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
            keep_count = int(sys.argv[3]) if len(sys.argv) > 3 else 10
            backup_manager.cleanup_old_backups(keep_days, keep_count)
            print("Cleanup completed")

        elif command == "stats":
            stats = backup_manager.get_backup_stats()
            print("Backup Statistics:")
            print(f"Total backups: {stats['total_backups']}")
            print(f"Total size: {stats['total_size'] / (1024*1024):.1f} MB")
            if stats['oldest_backup']:
                print(f"Oldest backup: {stats['oldest_backup'].strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Newest backup: {stats['newest_backup'].strftime('%Y-%m-%d %H:%M:%S')}")
            print("Backup types:")
            for btype, count in stats['backup_types'].items():
                print(f"  {btype}: {count}")

        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
