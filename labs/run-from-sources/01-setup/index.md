# Setup

Keeptrack needs three tools to run from its sources: Git, the .NET SDK and MongoDB.
We start by installing them in the container that has just been created for this lab.

> [!NOTE]
> The lab runs Debian 12 as a user with no administrator rights and this lab can be reproduced on any Linux machine.

## Git

1. Download and unpack Git, and `less`, the pager Git uses, then add them to the `PATH`:

   <!-- verify: requires=network timeout=180 -->

   ```bash exec
   cd ~ && \
   wget -q "${DEBIAN_MIRROR}/pool/main/g/git/${GIT_DEB}" -O git.deb && \
   wget -q "${DEBIAN_MIRROR}/pool/main/l/less/${LESS_DEB}" -O less.deb && \
   dpkg-deb -x git.deb ~/.local/ && \
   dpkg-deb -x less.deb ~/.local/ && \
   rm git.deb less.deb && \
   export PATH="$HOME/.local/usr/bin:$HOME/.local/usr/lib/git-core:$PATH" && \
   echo 'export PATH="$HOME/.local/usr/bin:$HOME/.local/usr/lib/git-core:$PATH"' >> ~/.bashrc && \
   export GIT_EXEC_PATH="$HOME/.local/usr/lib/git-core" && \
   echo 'export GIT_EXEC_PATH="$HOME/.local/usr/lib/git-core"' >> ~/.bashrc && \
   export PAGER=less && \
   echo 'export PAGER=less' >> ~/.bashrc && \
   git config --global init.templateDir "$HOME/.local/usr/share/git-core/templates"
   ```

   > [!NOTE]
   > `GIT_EXEC_PATH` and `init.templateDir` are only needed because Git is not in its usual location, `/usr`.

2. Check the version:

   <!-- verify: expect="git version 2." -->

   ```bash exec
   git --version
   ```

## .NET SDK

Keeptrack targets .NET 10, the current LTS.
On a workstation the SDK comes from the installer of the system (`winget install Microsoft.DotNet.SDK.10`, the macOS package, the Linux package manager).
Without administrator rights, the documented way is the official `dotnet-install.sh` script.

1. Download the script, its signature and the public key it is signed with, then verify it:

   <!-- verify: requires=network timeout=120 expect="Good signature from" -->

   ```bash exec
   cd ~ && \
   wget -q "${DOTNET_INSTALL_URL}/dotnet-install.sh" "${DOTNET_INSTALL_URL}/dotnet-install.sig" "${DOTNET_INSTALL_URL}/dotnet-install.asc" && \
   gpg --import dotnet-install.asc && \
   gpg --verify dotnet-install.sig dotnet-install.sh
   ```

   > [!NOTE]
   > `gpg` warns that the key is not certified: it only says the key is not in a trusted keyring.
   > `Good signature` is the result that matters.

2. Install the SDK in `~/.dotnet`, then delete the downloaded files:

   <!-- verify: requires=network timeout=300 expect="Installation finished successfully" -->

   ```bash exec
   cd ~ && \
   chmod +x dotnet-install.sh && \
   ./dotnet-install.sh --version "${DOTNET_SDK_VERSION}" --install-dir ~/.dotnet && \
   rm dotnet-install.sh dotnet-install.sig dotnet-install.asc
   ```

3. Set `DOTNET_ROOT` and the `PATH`, and turn off the welcome banner and the usage data the SDK sends by default:

   ```bash exec
   export DOTNET_ROOT="$HOME/.dotnet" && \
   export PATH="$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools" && \
   export DOTNET_NOLOGO=1 && \
   export DOTNET_CLI_TELEMETRY_OPTOUT=1 && \
   echo 'export DOTNET_ROOT="$HOME/.dotnet"' >> ~/.bashrc && \
   echo 'export PATH="$PATH:$DOTNET_ROOT:$DOTNET_ROOT/tools"' >> ~/.bashrc && \
   echo 'export DOTNET_NOLOGO=1' >> ~/.bashrc && \
   echo 'export DOTNET_CLI_TELEMETRY_OPTOUT=1' >> ~/.bashrc
   ```

4. List the SDK and the runtimes it carries, ASP.NET Core included:

   <!-- verify: expect="Microsoft.AspNetCore.App 10." -->

   ```bash exec
   dotnet --list-sdks && dotnet --list-runtimes
   ```

## MongoDB

Keeptrack stores the data in a MongoDB database.
As we run the lab in a container, we'll use a local `mongod`, with `mongosh` to create the indexes: both are archives MongoDB publishes, checked against their SHA-256.

1. Download MongoDB Community Server and the MongoDB Shell, check them, and unpack them:

   <!-- verify: requires=network timeout=300 expect="mongosh-linux-x64.tgz: OK" -->

   ```bash exec
   cd ~ && \
   wget -q "https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-debian12-${MONGODB_VERSION}.tgz" -O mongodb-linux-x86_64.tgz && \
   wget -q "https://github.com/mongodb-js/mongosh/releases/download/v${MONGOSH_VERSION}/mongosh-${MONGOSH_VERSION}-linux-x64.tgz" -O mongosh-linux-x64.tgz && \
   echo "${MONGODB_SHA256}  mongodb-linux-x86_64.tgz" | sha256sum -c && \
   echo "${MONGOSH_SHA256}  mongosh-linux-x64.tgz" | sha256sum -c && \
   mkdir -p ~/.local/mongodb && \
   tar xzf mongodb-linux-x86_64.tgz -C ~/.local/mongodb --strip-components 1 && \
   tar xzf mongosh-linux-x64.tgz -C ~/.local/mongodb --strip-components 1 && \
   rm mongodb-linux-x86_64.tgz mongosh-linux-x64.tgz
   ```

2. `mongod` links to `libcurl.so.4`, which the lab image lacks: unpack the Debian package, and point the dynamic loader to it.

   <!-- verify: requires=network timeout=120 -->

   ```bash exec
   cd ~ && \
   wget -q "${DEBIAN_MIRROR}/pool/main/c/curl/${LIBCURL_DEB}" -O libcurl4.deb && \
   dpkg-deb -x libcurl4.deb ~/.local/ && \
   rm libcurl4.deb && \
   export LD_LIBRARY_PATH="$HOME/.local/usr/lib/x86_64-linux-gnu" && \
   echo 'export LD_LIBRARY_PATH="$HOME/.local/usr/lib/x86_64-linux-gnu"' >> ~/.bashrc
   ```

   > [!NOTE]
   > On a machine with administrator rights, `apt-get install libcurl4` does the same.

3. Add both tools to the `PATH`, and check their versions:

   <!-- verify: expect="db version v9." -->

   ```bash exec
   export PATH="$HOME/.local/mongodb/bin:$PATH" && \
   echo 'export PATH="$HOME/.local/mongodb/bin:$PATH"' >> ~/.bashrc && \
   mongod --version | head -n 1 && \
   mongosh --version
   ```
