The test directory has certificate and private key files
used for communications library unit tests. These
certificates need to be renewed from time to time. When
the certs have expired, UTs will fail due to SSL not being
able to decrypt messages.

To generate new certificates, run the shell script in this
directory:
<pre><code>$ sh ./create-new-certs.sh noironetworks.com
</code></pre>

You can verify that the certs are valid using:
<pre><code>$ openssl verify -CAfile test/ca.pem test/server.pem
</code></pre>
