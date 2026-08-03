#!/usr/bin/env python3
import logging
import os
import re
import json
import subprocess
import shutil
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class ReproConfig:
    __slots__ = ('binary_path', 'binary_name', 'architecture', 'libc_version', 'exploit_script_path', 'network_ports', 'environment_vars', 'additional_files', 'run_as_non_root', 'enable_gdbserver', 'gdbserver_port',)

    def __init__(self, binary_path, binary_name='', architecture='amd64', libc_version='', exploit_script_path='', network_ports=None, environment_vars=None, additional_files=None, run_as_non_root=True, enable_gdbserver=False, gdbserver_port=1234):
        self.binary_path = binary_path
        self.binary_name = binary_name
        self.architecture = architecture
        self.libc_version = libc_version
        self.exploit_script_path = exploit_script_path
        self.network_ports = network_ports if network_ports is not None else []
        self.environment_vars = environment_vars if environment_vars is not None else {}
        self.additional_files = additional_files if additional_files is not None else []
        self.run_as_non_root = run_as_non_root
        self.enable_gdbserver = enable_gdbserver
        self.gdbserver_port = gdbserver_port



@dataclass
class GeneratedFile:
    file_name: str = ""
    content: str = ""
    file_path: str = ""

class ReproducerGenerator:
    # 漏洞利用 reproduction environment generator

    LIBC_VERSION_MAP = {
        '2.31': {
            'ubuntu': 'ubuntu:20.04',
            'debian': 'debian:bullseye',
            'glibc': 'debian:bullseye'
        },
        '2.35': {
            'ubuntu': 'ubuntu:22.04',
            'debian': 'debian:bookworm',
            'glibc': 'debian:bookworm'
        },
        '2.27': {
            'ubuntu': 'ubuntu:18.04',
            'debian': 'debian:buster',
            'glibc': 'debian:buster'
        },
        '2.28': {
            'ubuntu': 'ubuntu:19.04',
            'debian': 'debian:buster',
            'glibc': 'debian:buster'
        },
        '2.33': {
            'ubuntu': 'ubuntu:21.04',
            'debian': 'debian:bullseye',
            'glibc': 'debian:bullseye'
        },
        '2.34': {
            'ubuntu': 'ubuntu:21.10',
            'debian': 'debian:bullseye',
            'glibc': 'debian:bullseye'
        },
        '2.36': {
            'ubuntu': 'ubuntu:23.04',
            'debian': 'debian:bookworm',
            'glibc': 'debian:bookworm'
        },
        '2.37': {
            'ubuntu': 'ubuntu:23.10',
            'debian': 'debian:trixie',
            'glibc': 'debian:trixie'
        },
        '2.38': {
            'ubuntu': 'ubuntu:24.04',
            'debian': 'debian:trixie',
            'glibc': 'debian:trixie'
        },
        '2.23': {
            'ubuntu': 'ubuntu:16.04',
            'debian': 'debian:stretch',
            'glibc': 'debian:stretch'
        },
        '2.24': {
            'ubuntu': 'ubuntu:17.04',
            'debian': 'debian:stretch',
            'glibc': 'debian:stretch'
        },
        '2.25': {
            'ubuntu': 'ubuntu:17.10',
            'debian': 'debian:stretch',
            'glibc': 'debian:stretch'
        },
        '2.26': {
            'ubuntu': 'ubuntu:18.04',
            'debian': 'debian:buster',
            'glibc': 'debian:buster'
        }
    }

    ARCHITECTURE_MAP = {
        'amd64': '',
        'i386': '-i386',
        'arm64': '-arm64',
        'armhf': '-armhf'
    }

    def __init__(self, config):
        self.config = config
        self.generated_files = []
        self.output_dir = ''

        if self.config is not None:
            if not self.config.binary_name and self.config.binary_path is not None:
                self.config.binary_name = os.path.basename(self.config.binary_path)

    def select_base_image(self):
        sLibcVersion = self.config.libc_version if self.config is not None else ''

        if sLibcVersion in self.LIBC_VERSION_MAP:
            sImage = self.LIBC_VERSION_MAP[sLibcVersion]['debian']
        else:
            sImage = 'debian:bullseye'

        sArchSuffix = self.ARCHITECTURE_MAP.get(self.config.architecture, '') if self.config is not None else ''
        return "%s%s" % (sImage, sArchSuffix)

    def generate_dockerfile(self):
        if self.config is None:
            return ''

        sBaseImage = self.select_base_image()
        dockerfile_lines = [
            'FROM %s' % sBaseImage,
            '',
            '# Vulnerability reproduction environment',
            '# BinMind Binary Vulnerability Analysis Tool',
            '',
            '# Working directory',
            'WORKDIR /exploit',
            '',
            '# System dependencies',
            'RUN apt-get update && apt-get install -y --no-install-recommends \\',
            '    gdb \\',
            '    gdbserver \\',
            '    python3 \\',
            '    python3-pip \\',
            '    libc6-dbg \\',
            '    patchelf \\',
            '    && rm -rf /var/lib/apt/lists/*',
            '',
            '# Pwntools',
            'RUN pip3 install --no-cache-dir pwntools'
        ]

        if self.config.run_as_non_root:
            dockerfile_lines.extend([
                '',
                '# Non-root user',
                'RUN useradd -m -s /bin/bash vulnuser',
                'USER vulnuser'
            ])

        dockerfile_lines.extend([
            '',
            '# Binary and auxiliary files',
            'COPY %s /exploit/' % self.config.binary_name,
        ])

        if self.config.exploit_script_path is not None and self.config.exploit_script_path:
            sExploitName = os.path.basename(self.config.exploit_script_path)
            dockerfile_lines.append('COPY %s /exploit/' % sExploitName)

        if self.config.additional_files is not None:
            iSz = len(self.config.additional_files)
            i = 0
            while i < iSz:
                sAdditionalFile = self.config.additional_files[i]
                if sAdditionalFile is not None:
                    sFileName = os.path.basename(sAdditionalFile)
                    dockerfile_lines.append('COPY %s /exploit/' % sFileName)
                i += 1

        if self.config.libc_version:
            dockerfile_lines.extend([
                '',
                '# Custom libc library path',
                'ENV LD_LIBRARY_PATH=/exploit:$LD_LIBRARY_PATH'
            ])

        if self.config.environment_vars is not None:
            for sKey, sValue in self.config.environment_vars.items():
                dockerfile_lines.append('ENV %s=%s' % (sKey, sValue))

        if self.config.enable_gdbserver:
            dockerfile_lines.extend([
                '',
                'EXPOSE %d' % self.config.gdbserver_port,
                '',
                '# Entrypoint: gdbserver',
                'CMD ["gdbserver", "--once", "0.0.0.0:%d", "./%s"]' % (self.config.gdbserver_port, self.config.binary_name)
            ])
        else:
            dockerfile_lines.extend([
                '',
                '# Entrypoint: execute binary',
                'CMD ["./%s"]' % self.config.binary_name
            ])

        return '\n'.join(dockerfile_lines)

    def generate_docker_compose(self):
        if self.config is None:
            return '{}'

        compose_config = {
            'version': '3.8',
            'services': {
                'vuln-repro': {
                    'build': {
                        'context': '.',
                        'dockerfile': 'Dockerfile'
                    },
                    'container_name': 'vuln-repro-container',
                    'volumes': [
                        './:/exploit'
                    ],
                    'network_mode': 'bridge'
                }
            }
        }

        if self.config.network_ports is not None and len(self.config.network_ports) > 0:
            ports = []
            for iPort in self.config.network_ports:
                ports.append('%d:%d' % (iPort, iPort))
            compose_config['services']['vuln-repro']['ports'] = ports

        if self.config.enable_gdbserver:
            if 'ports' not in compose_config['services']['vuln-repro']:
                compose_config['services']['vuln-repro']['ports'] = []
            compose_config['services']['vuln-repro']['ports'].append(
                '%d:%d' % (self.config.gdbserver_port, self.config.gdbserver_port)
            )

        return json.dumps(compose_config, indent=2)

    def generate_readme(self):
        if self.config is None:
            return ''

        sBinaryName = self.config.binary_name if self.config.binary_name is not None else 'unknown'
        sArch = self.config.architecture if self.config.architecture is not None else 'unknown'
        sLibcVer = self.config.libc_version if self.config.libc_version else "system default"
        bGdbEnabled = self.config.enable_gdbserver

        readme_lines = [
            '# %s Reproduction Environment' % sBinaryName,
            '',
            '## Environment',
            '',
            '- **Target binary**: %s' % sBinaryName,
            '- **Architecture**: %s' % sArch,
            '- **Libc version**: %s' % sLibcVer,
            '- **GDB Server**: %s' % ("Enabled" if bGdbEnabled else "Disabled"),
            '',
            '## Quick Start',
            '',
            '### Build Image',
            '',
            '```bash',
            'docker-compose build',
            '```',
            '',
            '### Run Container',
            '',
            '```bash',
            'docker-compose up -d',
            '```',
            '',
            '### Enter Container',
            '',
            '```bash',
            'docker exec -it vuln-repro-container /bin/bash',
            '```',
            '',
            '### Debug Mode',
            ''
        ]

        if bGdbEnabled:
            readme_lines.extend([
                'GDB Server active: connect from external debugger:',
                '',
                '```bash',
                'gdb-multiarch %s' % sBinaryName,
                '(gdb) target remote localhost:%d' % self.config.gdbserver_port,
                '```',
                ''
            ])

        readme_lines.extend([
            '## Vulnerability Info',
            '',
            '### Detected Protections',
            '',
            '| Protection | Status |',
            '|----------|------|',
            '| NX | TBD |',
            '| PIE | TBD |',
            '| RELRO | TBD |',
            '| Canary | TBD |',
            '',
            '## File Structure',
            '',
            '```',
            '/exploit/',
            '    %s    # Target binary' % sBinaryName,
        ])

        if self.config.exploit_script_path is not None and self.config.exploit_script_path:
            sExploitName = os.path.basename(self.config.exploit_script_path)
            readme_lines.append('    %s      # Exploit script' % sExploitName)

        readme_lines.extend([
            '    Dockerfile         # Docker configuration',
            '```',
            '',
            '## Notes',
            '',
            '- For security research and vulnerability reproduction only',
            '- Not for unauthorized use',
            '- Ensure proper authorization before use',
            '- Run in an isolated network environment'
        ])

        return '\n'.join(readme_lines)

    def generate_all(self, sOutputDir):
        logger.info("[ReproEnv] Generating reproduction environment to: %s", sOutputDir)

        if sOutputDir is not None:
            os.makedirs(sOutputDir, exist_ok=True)
        self.output_dir = sOutputDir

        sDockerfileContent = self.generate_dockerfile()
        dockerfile = GeneratedFile(
            file_name='Dockerfile',
            content=sDockerfileContent,
            file_path=os.path.join(sOutputDir, 'Dockerfile')
        )

        if dockerfile.file_path is not None:
            with open(dockerfile.file_path, 'w', encoding='utf-8') as f:
                if dockerfile.content is not None:
                    f.write(dockerfile.content)
        self.generated_files.append(dockerfile)
        logger.info("[ReproEnv] Dockerfile written: %s", dockerfile.file_path)

        sDockerComposeContent = self.generate_docker_compose()
        docker_compose = GeneratedFile(
            file_name='docker-compose.yml',
            content=sDockerComposeContent,
            file_path=os.path.join(sOutputDir, 'docker-compose.yml')
        )

        if docker_compose.file_path is not None:
            with open(docker_compose.file_path, 'w', encoding='utf-8') as f:
                if docker_compose.content is not None:
                    f.write(docker_compose.content)
        self.generated_files.append(docker_compose)
        logger.info("[ReproEnv] docker-compose.yml written: %s", docker_compose.file_path)

        sReadmeContent = self.generate_readme()
        readme = GeneratedFile(
            file_name='README.md',
            content=sReadmeContent,
            file_path=os.path.join(sOutputDir, 'README.md')
        )

        if readme.file_path is not None:
            with open(readme.file_path, 'w', encoding='utf-8') as f:
                if readme.content is not None:
                    f.write(readme.content)
        self.generated_files.append(readme)
        logger.info("[ReproEnv] README.md written: %s", readme.file_path)

        if self.config is not None:
            if self.config.exploit_script_path is not None and self.config.exploit_script_path and os.path.exists(self.config.exploit_script_path):
                sExploitDest = os.path.join(sOutputDir, os.path.basename(self.config.exploit_script_path))
                shutil.copy(self.config.exploit_script_path, sExploitDest)
                logger.info("[ReproEnv] Exploit script copied: %s", sExploitDest)

            if self.config.binary_path is not None and self.config.binary_path and os.path.exists(self.config.binary_path):
                sBinaryDest = os.path.join(sOutputDir, self.config.binary_name)
                shutil.copy(self.config.binary_path, sBinaryDest)
                logger.info("[ReproEnv] Target binary copied: %s", sBinaryDest)

            if self.config.additional_files is not None:
                for sAdditionalFile in self.config.additional_files:
                    if sAdditionalFile is not None and os.path.exists(sAdditionalFile):
                        sFileDest = os.path.join(sOutputDir, os.path.basename(sAdditionalFile))
                        shutil.copy(sAdditionalFile, sFileDest)
                        logger.info("[ReproEnv] Additional file copied: %s", sFileDest)

        logger.info("[ReproEnv] Environment generation complete: %d files", len(self.generated_files))
        return self.generated_files

    def validate_dockerfile(self):
        if not self.output_dir:
            logger.error("[ReproEnv] Output directory not set. Call generate_all first.")
            return False

        sDockerfilePath = os.path.join(self.output_dir, 'Dockerfile')
        if not os.path.exists(sDockerfilePath):
            logger.error("[ReproEnv] Dockerfile does not exist: %s", sDockerfilePath)
            return False

        try:
            result = subprocess.run(
                ['docker', 'build', '--dry-run', '-f', sDockerfilePath, self.output_dir],
                capture_output=True,
                text=True,
                timeout=60)
            if result.returncode == 0:
                logger.info("[ReproEnv] Dockerfile syntax validation passed")
                return True
            else:
                logger.warning("[ReproEnv] Dockerfile syntax validation failed: %s", result.stderr)
                return False

        except FileNotFoundError:
            logger.warning("[ReproEnv] Docker unavailable, skipping syntax validation")
            return self._validate_dockerfile_simple()
        except subprocess.TimeoutExpired:
            logger.warning("[ReproEnv] Docker validation timed out")
            return False
        except Exception as e:
            logger.warning("[ReproEnv] Docker validation error: %s", e)
            return False

    def _validate_dockerfile_simple(self):
        sDockerfilePath = os.path.join(self.output_dir, 'Dockerfile')
        if not os.path.exists(sDockerfilePath):
            return False

        with open(sDockerfilePath, 'r', encoding='utf-8') as f:
            sContent = f.read()

        if sContent is None:
            return False

        valid_commands = [
            'FROM', 'RUN', 'COPY', 'ADD', 'ENV', 'WORKDIR',
            'USER', 'EXPOSE', 'CMD', 'ENTRYPOINT', 'LABEL',
            'ARG', 'ONBUILD', 'STOPSIGNAL', 'HEALTHCHECK', 'SHELL'
        ]

        lines = sContent.split('\n')
        bInMultiline = False

        i = 0
        iSz = len(lines)
        while i < iSz:
            sLine = lines[i]
            if sLine is not None:
                sStripped = sLine.strip()

                if sStripped and not sStripped.startswith('#'):

                    if sStripped.endswith('\\'):
                        bInMultiline = True
                        i += 1
                        continue

                    if bInMultiline:
                        bInMultiline = False
                        i += 1
                        continue

                    parts = sStripped.split()
                    if parts:
                        sCmd = parts[0].upper()
                        if sCmd not in valid_commands:
                            logger.warning("[ReproEnv] Dockerfile line %d: unknown command '%s'", i + 1, sCmd)
                            return False

                elif not sStripped or sStripped.startswith('#'):
                    pass

            i += 1

        if 'FROM' not in sContent:
            logger.warning("[ReproEnv] Dockerfile missing FROM command")
            return False

        logger.info("[ReproEnv] Dockerfile basic validation passed")
        return True

    def get_quick_start_commands(self):
        commands = []

        if self.output_dir:
            commands.append("cd %s" % self.output_dir)
            commands.append("docker-compose build")
            commands.append("docker-compose up -d")
            commands.append("docker exec -it vuln-repro-container /bin/bash")

        return commands

    def generate(self, sOutputDir):
        logger.info("[ReproEnv] Building exploit reproduction environment")

        generated_files = self.generate_all(sOutputDir)
        bValidationResult = self.validate_dockerfile()

        iCount = len(generated_files) if generated_files is not None else 0
        aFileInfos = []
        i = 0
        while i < iCount:
            f = generated_files[i]
            if f is not None:
                iFileSize = len(f.content) if f.content is not None else 0
                aFileInfos.append({
                    'file_name': f.file_name,
                    'file_path': f.file_path,
                    'size': iFileSize
                })
            i += 1

        result = {
            'success': True,
            'output_dir': sOutputDir,
            'generated_files': aFileInfos,
            'base_image': self.select_base_image(),
            'validation_passed': bValidationResult,
            'quick_start_commands': self.get_quick_start_commands(),
            'config': {
                'binary_name': self.config.binary_name if self.config is not None else '',
                'architecture': self.config.architecture if self.config is not None else '',
                'libc_version': self.config.libc_version if self.config is not None else '',
                'run_as_non_root': self.config.run_as_non_root if self.config is not None else True,
                'enable_gdbserver': self.config.enable_gdbserver if self.config is not None else False,
                'network_ports': self.config.network_ports if self.config is not None else []
            },
            'summary': {
                'total_files': len(generated_files) if generated_files is not None else 0,
                'dockerfile_generated': True,
                'docker_compose_generated': True,
                'readme_generated': True,
                'validation_passed': bValidationResult
            }
        }

        logger.info("[ReproEnv] Reproduction environment build complete")
        return result


def generate_repro_environment(binary_path, output_dir, libc_version='', architecture='amd64', exploit_script_path='', network_ports=None, environment_vars=None, additional_files=None, run_as_non_root=True, enable_gdbserver=False, gdbserver_port=1234):
    config = ReproConfig(
        binary_path=binary_path,
        architecture=architecture,
        libc_version=libc_version,
        exploit_script_path=exploit_script_path,
        network_ports=network_ports if network_ports is not None else [],
        environment_vars=environment_vars if environment_vars is not None else {},
        additional_files=additional_files if additional_files is not None else [],
        run_as_non_root=run_as_non_root,
        enable_gdbserver=enable_gdbserver,
        gdbserver_port=gdbserver_port
    )

    generator = ReproducerGenerator(config)
    return generator.generate(output_dir)
