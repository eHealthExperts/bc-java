package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TlsServerProtocol
    extends TlsProtocol
{
    private static final Logger LOG = LoggerFactory.getLogger(TlsServerProtocol.class);
    
    protected TlsServer tlsServer = null;
    TlsServerContextImpl tlsServerContext = null;

    protected int[] offeredCipherSuites = null;
    protected TlsKeyExchange keyExchange = null;
    protected CertificateRequest certificateRequest = null;
    protected byte[] serverFinishedTranscriptHash = null;
    protected boolean offeredExtendedMasterSecret;

    /**
     * Constructor for non-blocking mode.<br>
     * <br>
     * When data is received, use {@link #offerInput(byte[])} to provide the received ciphertext,
     * then use {@link #readInput(byte[], int, int)} to read the corresponding cleartext.<br>
     * <br>
     * Similarly, when data needs to be sent, use {@link #writeApplicationData(byte[], int, int)} to
     * provide the cleartext, then use {@link #readOutput(byte[], int, int)} to get the
     * corresponding ciphertext.
     */
    public TlsServerProtocol()
    {
        super();
    }

    /**
     * Constructor for blocking mode.
     * @param input The stream of data from the client
     * @param output The stream of data to the client
     */
    public TlsServerProtocol(InputStream input, OutputStream output)
    {
        super(input, output);
    }

    /**
     * Receives a TLS handshake in the role of server.<br>
     * <br>
     * In blocking mode, this will not return until the handshake is complete.
     * In non-blocking mode, use {@link TlsPeer#notifyHandshakeComplete()} to
     * receive a callback when the handshake is complete.
     *
     * @param tlsServer
     * @throws IOException If in blocking mode and handshake was not successful.
     */
    public void accept(TlsServer tlsServer)
        throws IOException
    {
        if (tlsServer == null)
        {
            throw new IllegalArgumentException("'tlsServer' cannot be null");
        }
        if (this.tlsServer != null)
        {
            throw new IllegalStateException("'accept' can only be called once");
        }

        LOG.debug("Receives a TLS handshake in the role of server.");
        this.tlsServer = tlsServer;
        this.tlsServerContext = new TlsServerContextImpl(tlsServer.getCrypto());

        this.tlsServer.init(tlsServerContext);
        this.recordStream.init(tlsServerContext);

        tlsServer.notifyCloseHandle(this);

        beginHandshake(false);

        if (blocking)
        {
            blockForHandshake();
        }
    }

//    public boolean renegotiate() throws IOException
//    {
//        boolean allowed = super.renegotiate();
//        if (allowed)
//        {
//            sendHelloRequestMessage();
//        }
//        return allowed;
//    }

    protected void cleanupHandshake()
    {
        super.cleanupHandshake();

        this.offeredCipherSuites = null;
        this.keyExchange = null;
        this.certificateRequest = null;
        this.serverFinishedTranscriptHash = null;
        this.offeredExtendedMasterSecret = false;
    }

    protected boolean expectCertificateVerifyMessage()
    {
        Certificate clientCertificate = tlsServerContext.getSecurityParametersHandshake().getPeerCertificate();

        return null != clientCertificate && !clientCertificate.isEmpty() && keyExchange.requiresCertificateVerify();
    }

    protected ServerHello generate13ServerHello(boolean afterHelloRetryRequest) throws IOException
    {
        // TODO[tls13]
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected ServerHello generateServerHelloMessage()
        throws IOException
    {
        SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();

        /*
         * NOTE: Currently no server support for session resumption
         * 
         * If adding support, ensure securityParameters.tlsUnique is set to the localVerifyData, but
         * ONLY when extended_master_secret has been negotiated (otherwise NULL).
         */
        {
            invalidateSession();

            securityParameters.sessionID = TlsUtils.EMPTY_BYTES;

            this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);
            this.sessionParameters = null;
            this.sessionMasterSecret = null;
        }

        // TODO[tls13] Negotiate cipher suite first?

        ProtocolVersion server_version;
        if (securityParameters.isRenegotiating())
        {
            // Always select the negotiated version from the initial handshake
            server_version = tlsServerContext.getServerVersion();
        }
        else
        {
            server_version = tlsServer.getServerVersion();
            if (!ProtocolVersion.contains(tlsServerContext.getClientSupportedVersions(), server_version))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            securityParameters.negotiatedVersion = server_version;
        }

        TlsUtils.negotiatedVersionTLSServer(tlsServerContext);

        final boolean negotiatedTLSv13Plus = ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(server_version);

        // TODO[tls13] At some point after here we should redirect to generate13ServerHello
//        if (negotiatedTLSv13Plus)
//        {
//            return generate13ServerHello(false);
//        }

        {
            ProtocolVersion legacy_record_version = negotiatedTLSv13Plus ? ProtocolVersion.TLSv12 : server_version;

            recordStream.setWriteVersion(legacy_record_version);
        }

        /*
         * TODO[tls13] Send ServerHello message that MAY be a HelloRetryRequest.
         * 
         * For HelloRetryRequest, state => CS_SERVER_HELLO_RETRY_REQUEST instead (and no further
         * messages), and reset Transcript-Hash to begin with synthetic 'message_hash' message
         * having Hash(ClientHello) as the message body.
         */

        {
            boolean useGMTUnixTime = !negotiatedTLSv13Plus && tlsServer.shouldUseGMTUnixTime();

            securityParameters.serverRandom = createRandomBlock(useGMTUnixTime, tlsServerContext);

            if (!server_version.equals(ProtocolVersion.getLatestTLS(tlsServer.getProtocolVersions())))
            {
                TlsUtils.writeDowngradeMarker(server_version, securityParameters.getServerRandom());
            }
        }

        {
            int cipherSuite = tlsServer.getSelectedCipherSuite();
            LOG.debug("Selected CipherSuite [{}]", cipherSuite);
            if (!TlsUtils.isValidCipherSuiteSelection(offeredCipherSuites, cipherSuite) ||
                !TlsUtils.isValidVersionForCipherSuite(cipherSuite, securityParameters.getNegotiatedVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            TlsUtils.negotiatedCipherSuite(securityParameters, cipherSuite);
        }

        this.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(tlsServer.getServerExtensions());

        ProtocolVersion legacy_version = server_version;
        if (negotiatedTLSv13Plus)
        {
            legacy_version = ProtocolVersion.TLSv12;

            TlsExtensionsUtils.addSupportedVersionsExtensionServer(serverExtensions, server_version);
        }

        if (securityParameters.isRenegotiating())
        {
            /*
             * The server MUST include a "renegotiation_info" extension containing the saved
             * client_verify_data and server_verify_data in the ServerHello.
             */
            if (!securityParameters.isSecureRenegotiation())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            SecurityParameters saved = tlsServerContext.getSecurityParametersConnection();
            byte[] reneg_conn_info = TlsUtils.concat(saved.getPeerVerifyData(), saved.getLocalVerifyData());

            this.serverExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(reneg_conn_info));
        }
        else
        {
            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake
             */
            if (securityParameters.isSecureRenegotiation())
            {
                byte[] renegExtData = TlsUtils.getExtensionData(this.serverExtensions, EXT_RenegotiationInfo);
                boolean noRenegExt = (null == renegExtData);

                if (noRenegExt)
                {
                    /*
                     * Note that sending a "renegotiation_info" extension in response to a ClientHello
                     * containing only the SCSV is an explicit exception to the prohibition in RFC 5246,
                     * Section 7.4.1.4, on the server sending unsolicited extensions and is only allowed
                     * because the client is signaling its willingness to receive the extension via the
                     * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV.
                     */

                    /*
                     * If the secure_renegotiation flag is set to TRUE, the server MUST include an empty
                     * "renegotiation_info" extension in the ServerHello message.
                     */
                    this.serverExtensions.put(EXT_RenegotiationInfo, createRenegotiationInfo(TlsUtils.EMPTY_BYTES));
                }
            }
        }

        /*
         * RFC 7627 4. Clients and servers SHOULD NOT accept handshakes that do not use the extended
         * master secret [..]. (and see 5.2, 5.3)
         * 
         * RFC 8446 Appendix D. Because TLS 1.3 always hashes in the transcript up to the server
         * Finished, implementations which support both TLS 1.3 and earlier versions SHOULD indicate
         * the use of the Extended Master Secret extension in their APIs whenever TLS 1.3 is used.
         */
        if (TlsUtils.isTLSv13(server_version))
        {
            securityParameters.extendedMasterSecret = true;
        }
        else
        {
            securityParameters.extendedMasterSecret = offeredExtendedMasterSecret && !server_version.isSSL()
                && tlsServer.shouldUseExtendedMasterSecret();

            if (securityParameters.isExtendedMasterSecret())
            {
                TlsExtensionsUtils.addExtendedMasterSecretExtension(serverExtensions);
            }
            else if (tlsServer.requiresExtendedMasterSecret())
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            else if (resumedSession && !tlsServer.allowLegacyResumption())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
        }

        /*
         * RFC 7301 3.1. When session resumption or session tickets [...] are used, the previous
         * contents of this extension are irrelevant, and only the values in the new handshake
         * messages are considered.
         */
        securityParameters.applicationProtocol = TlsExtensionsUtils.getALPNExtensionServer(serverExtensions);
        securityParameters.applicationProtocolSet = true;

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */

        if (!this.serverExtensions.isEmpty())
        {
            securityParameters.encryptThenMAC = TlsExtensionsUtils.hasEncryptThenMACExtension(serverExtensions);

            securityParameters.maxFragmentLength = processMaxFragmentLengthExtension(clientExtensions,
                serverExtensions, AlertDescription.internal_error);

            securityParameters.truncatedHMac = TlsExtensionsUtils.hasTruncatedHMacExtension(serverExtensions);

            if (!resumedSession)
            {
                // TODO[tls13] See RFC 8446 4.4.2.1
                if (TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsExtensionsUtils.EXT_status_request_v2,
                    AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 2;
                }
                else if (TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsExtensionsUtils.EXT_status_request,
                    AlertDescription.internal_error))
                {
                    securityParameters.statusRequestVersion = 1;
                }
            }

            this.expectSessionTicket = !resumedSession
                && TlsUtils.hasExpectedEmptyExtensionData(serverExtensions, TlsProtocol.EXT_SessionTicket,
                    AlertDescription.internal_error);
        }

        applyMaxFragmentLengthExtension();

        return new ServerHello(legacy_version, securityParameters.getServerRandom(), tlsSession.getSessionID(),
            securityParameters.getCipherSuite(), serverExtensions);
    }

    protected TlsContext getContext()
    {
        return tlsServerContext;
    }

    AbstractTlsContext getContextAdmin()
    {
        return tlsServerContext;
    }

    protected TlsPeer getPeer()
    {
        return tlsServer;
    }

    protected void handle13HandshakeMessage(short type, HandshakeMessageInput buf)
        throws IOException
    {
        if (!isTLSv13ConnectionState())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (this.resumedSession)
        {
            /*
             * TODO[tls13] Abbreviated handshakes (PSK resumption)
             * 
             * NOTE: No CertificateRequest, Certificate, CertificateVerify messages, but client
             * might now send EndOfEarlyData after receiving server Finished message.
             */
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        switch (type)
        {
        case HandshakeType.certificate:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_FINISHED:
            {
                receive13ClientCertificate(buf);
                this.connection_state = CS_CLIENT_CERTIFICATE;
            	LOG.trace("New connection state CS_CLIENT_CERTIFICATE");
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.certificate_verify:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_CERTIFICATE:
            {
                receive13ClientCertificateVerify(buf);
                buf.updateHash(handshakeHash);
                this.connection_state = CS_CLIENT_CERTIFICATE_VERIFY;
            	LOG.trace("New connection state CS_CLIENT_CERTIFICATE_VERIFY");
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.client_hello:
        {
            switch (this.connection_state)
            {
            case CS_START:
            {
                // NOTE: Legacy handler should be dispatching initial ClientHello.
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }
            case CS_SERVER_HELLO_RETRY_REQUEST:
            {
                receive13ClientHelloRetry(buf);
                this.connection_state = CS_CLIENT_HELLO_RETRY;
            	LOG.trace("New connection state CS_CLIENT_HELLO_RETRY");

                ServerHello serverHello = generate13ServerHello(true);
                sendServerHelloMessage(serverHello);
                this.connection_state = CS_SERVER_HELLO;
            	LOG.trace("New connection state CS_SERVER_HELLO");

                send13ServerHelloCoda(serverHello, true);
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.finished:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_FINISHED:
            {
                skip13ClientCertificate();
                // Fall through
            }
            case CS_CLIENT_CERTIFICATE:
            {
                skip13ClientCertificateVerify();
                // Fall through
            }
            case CS_CLIENT_CERTIFICATE_VERIFY:
            {
                receive13ClientFinished(buf);
                this.connection_state = CS_CLIENT_FINISHED;
            	LOG.trace("New connection state CS_CLIENT_FINISHED");

                TlsUtils.establish13PhaseApplication(tlsServerContext, serverFinishedTranscriptHash, recordStream);

                completeHandshake();
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.key_update:
        {
            switch (this.connection_state)
            {
            case CS_END:
            {
                receive13ClientKeyUpdate(buf);
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }

        case HandshakeType.certificate_request:
        case HandshakeType.certificate_status:
        case HandshakeType.certificate_url:
        case HandshakeType.client_key_exchange:
        case HandshakeType.encrypted_extensions:
        case HandshakeType.end_of_early_data:
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.message_hash:
        case HandshakeType.new_session_ticket:
        case HandshakeType.server_hello:
        case HandshakeType.server_hello_done:
        case HandshakeType.server_key_exchange:
        case HandshakeType.supplemental_data:
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void handleHandshakeMessage(short type, HandshakeMessageInput buf)
        throws IOException
    {
        LOG.debug("Handle HandshakeMessage [{}]", type);
        SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();

        if (connection_state > CS_CLIENT_HELLO
            && TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion()))
        {
            handle13HandshakeMessage(type, buf);
            return;
        }

        if (!isLegacyConnectionState())
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        if (this.resumedSession)
        {
            if (type != HandshakeType.finished || this.connection_state != CS_SERVER_FINISHED)
            {
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }

            processFinishedMessage(buf);
      
            this.connection_state = CS_CLIENT_FINISHED;
        	LOG.trace("New connection state CS_CLIENT_FINISHED");

            completeHandshake();
            return;
        }

        switch (type)
        {
        case HandshakeType.client_hello:
        {
            switch (this.connection_state)
            {
            case CS_END:
            {
                if (!handleRenegotiation())
                {
                    break;
                }

                // NB: Fall through to next case label
            }
            case CS_START:
            {
            	resetCurrentSession();
                securityParameters = tlsServerContext.getSecurityParametersHandshake();

                receiveClientHelloMessage(buf);
                this.connection_state = CS_CLIENT_HELLO;
            	LOG.trace("New connection state CS_CLIENT_HELLO");

                if(sessionParameters != null && tlsServer.getNeedClientAuth()) 
                {
                	if(sessionParameters.getPeerCertificate() == null) 
                	{
                		resetCurrentSession();
                	}
                }

                this.resumedSession = sessionParameters != null;
                if(!this.resumedSession) 
                {
                    securityParameters.sessionID = TlsUtils.generateSessionID(this.tlsServerContext.getCrypto().getSecureRandom());
                    
                    this.tlsSession = TlsUtils.importSession(securityParameters.getSessionID(), null);
                    this.sessionParameters = null;
                }
                
                ServerHello serverHello = generateServerHelloMessage();
                handshakeHash.notifyPRFDetermined();

                if (TlsUtils.isTLSv13(securityParameters.getNegotiatedVersion()))
                {
                    // TODO[tls13]
//                    throw new TlsFatalAlert(AlertDescription.internal_error);

                    if (serverHello.isHelloRetryRequest())
                    {
                        TlsUtils.adjustTranscriptForRetry(handshakeHash);
                        sendServerHelloMessage(serverHello);
                        this.connection_state = CS_SERVER_HELLO_RETRY_REQUEST;
                    	LOG.trace("New connection state CS_SERVER_HELLO_RETRY_REQUEST");
                    }
                    else
                    {
                        sendServerHelloMessage(serverHello);
                        this.connection_state = CS_SERVER_HELLO;
                    	LOG.trace("New connection state CS_SERVER_HELLO");

                        send13ServerHelloCoda(serverHello, false);
                    }
                    break;
                }

                sendServerHelloMessage(serverHello);
                this.connection_state = CS_SERVER_HELLO;
            	LOG.trace("New connection state CS_SERVER_HELLO");

                if(this.resumedSession) {
                	recordStream.setPendingConnectionState(TlsUtils.initCipher(getContext()));
                	
                    sendChangeCipherSpecMessage();
                    sendFinishedMessage();
                    this.connection_state = CS_SERVER_FINISHED;
                    
                    return;
                }

                Vector serverSupplementalData = tlsServer.getServerSupplementalData();
                if (serverSupplementalData != null)
                {
                    sendSupplementalDataMessage(serverSupplementalData);
                    this.connection_state = CS_SERVER_SUPPLEMENTAL_DATA;
                	LOG.trace("New connection state CS_SERVER_SUPPLEMENTAL_DATA");
                }

                this.keyExchange = TlsUtils.initKeyExchangeServer(tlsServerContext, tlsServer);

                TlsCredentials serverCredentials = TlsUtils.establishServerCredentials(tlsServer);

                // Server certificate
                {
                    Certificate serverCertificate = null;

                    ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
                    if (null == serverCredentials)
                    {
                        this.keyExchange.skipServerCredentials();
                    }
                    else
                    {
                        this.keyExchange.processServerCredentials(serverCredentials);

                        serverCertificate = serverCredentials.getCertificate();
                        sendCertificateMessage(serverCertificate, endPointHash);
                        this.connection_state = CS_SERVER_CERTIFICATE;
                        LOG.trace("New connection state CS_SERVER_CERTIFICATE");
                    }

                    securityParameters.tlsServerEndPoint = endPointHash.toByteArray();

                    // TODO[RFC 3546] Check whether empty certificates is possible, allowed, or excludes CertificateStatus
                    if (null == serverCertificate || serverCertificate.isEmpty())
                    {
                        securityParameters.statusRequestVersion = 0;
                    }
                }

                if (securityParameters.getStatusRequestVersion() > 0)
                {
                    CertificateStatus certificateStatus = tlsServer.getCertificateStatus();
                    if (certificateStatus != null)
                    {
                        sendCertificateStatusMessage(certificateStatus);
                        this.connection_state = CS_SERVER_CERTIFICATE_STATUS;
                    	LOG.trace("New connection state CS_SERVER_CERTIFICATE");
                    }
                }

                byte[] serverKeyExchange = this.keyExchange.generateServerKeyExchange();
                if (serverKeyExchange != null)
                {
                    sendServerKeyExchangeMessage(serverKeyExchange);
                    this.connection_state = CS_SERVER_KEY_EXCHANGE;
                	LOG.trace("New connection state CS_SERVER_KEY_EXCHANGE");
                }

                if (null != serverCredentials)
                {
                    this.certificateRequest = tlsServer.getCertificateRequest();

                    if (null == this.certificateRequest)
                    {
                        /*
                         * For static agreement key exchanges, CertificateRequest is required since
                         * the client Certificate message is mandatory but can only be sent if the
                         * server requests it.
                         */
                        if (!keyExchange.requiresCertificateVerify())
                        {
                            throw new TlsFatalAlert(AlertDescription.internal_error);
                        }
                    }
                    else
                    {
                        if (TlsUtils.isTLSv12(tlsServerContext) != (certificateRequest.getSupportedSignatureAlgorithms() != null))
                        {
                            throw new TlsFatalAlert(AlertDescription.internal_error);
                        }

                        this.certificateRequest = TlsUtils.validateCertificateRequest(this.certificateRequest, this.keyExchange);

                        TlsUtils.establishServerSigAlgs(securityParameters, certificateRequest);

                        TlsUtils.trackHashAlgorithms(handshakeHash, securityParameters.getServerSigAlgs());

                        sendCertificateRequestMessage(certificateRequest);
                        this.connection_state = CS_SERVER_CERTIFICATE_REQUEST;
                    	LOG.trace("New connection state CS_CERTIFICATE_REQUEST");
                    }
                }

                sendServerHelloDoneMessage();
                this.connection_state = CS_SERVER_HELLO_DONE;
            	LOG.trace("New connection state CS_SERVER_HELLO_DONE");

                boolean forceBuffering = false;
                TlsUtils.sealHandshakeHash(tlsServerContext, handshakeHash, forceBuffering);

                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.supplemental_data:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO_DONE:
            {
                tlsServer.processClientSupplementalData(readSupplementalDataMessage(buf));
                this.connection_state = CS_CLIENT_SUPPLEMENTAL_DATA;
            	LOG.trace("New connection state CS_CLIENT_SUPPLEMENTAL_DATA");
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.certificate:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO_DONE:
            {
                tlsServer.processClientSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_CLIENT_SUPPLEMENTAL_DATA:
            {
                if (this.certificateRequest == null)
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
                receiveCertificateMessage(buf);
                this.connection_state = CS_CLIENT_CERTIFICATE;
            	LOG.trace("New connection state CS_CLIENT_CERTIFICATE");
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.client_key_exchange:
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO_DONE:
            {
                tlsServer.processClientSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_CLIENT_SUPPLEMENTAL_DATA:
            {
                if (null == certificateRequest)
                {
                    this.keyExchange.skipClientCredentials();
                }
                else if (TlsUtils.isTLSv12(tlsServerContext))
                {
                    /*
                     * RFC 5246 If no suitable certificate is available, the client MUST send a
                     * certificate message containing no certificates.
                     * 
                     * NOTE: In previous RFCs, this was SHOULD instead of MUST.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
                else if (TlsUtils.isSSL(tlsServerContext))
                {
                    /*
                     * SSL 3.0 If the server has sent a certificate request Message, the client must
                     * send either the certificate message or a no_certificate alert.
                     */
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
                else
                {
                    notifyClientCertificate(Certificate.EMPTY_CHAIN);
                }
                // NB: Fall through to next case label
            }
            case CS_CLIENT_CERTIFICATE:
            {
                receiveClientKeyExchangeMessage(buf);
                this.connection_state = CS_CLIENT_KEY_EXCHANGE;
            	LOG.trace("New connection state CS_CLIENT_KEY_EXCHANGE");
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.certificate_verify:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_KEY_EXCHANGE:
            {
                /*
                 * RFC 5246 7.4.8 This message is only sent following a client certificate that has
                 * signing capability (i.e., all certificates except those containing fixed
                 * Diffie-Hellman parameters).
                 */
                if (!expectCertificateVerifyMessage())
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }

                receiveCertificateVerifyMessage(buf);
                buf.updateHash(handshakeHash);
                this.connection_state = CS_CLIENT_CERTIFICATE_VERIFY;
            	LOG.trace("New connection state CS_CERTIFICATE_VERIFY");
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }
        case HandshakeType.finished:
        {
            switch (this.connection_state)
            {
            case CS_CLIENT_KEY_EXCHANGE:
            {
                if (expectCertificateVerifyMessage())
                {
                    throw new TlsFatalAlert(AlertDescription.unexpected_message);
                }
                // NB: Fall through to next case label
            }
            case CS_CLIENT_CERTIFICATE_VERIFY:
            {
                processFinishedMessage(buf);
                buf.updateHash(handshakeHash);
                this.connection_state = CS_CLIENT_FINISHED;
            	LOG.trace("New connection state CS_CLIENT_FINISHED");

                if (this.expectSessionTicket)
                {
                    sendNewSessionTicketMessage(tlsServer.getNewSessionTicket());
                    this.connection_state = CS_SERVER_SESSION_TICKET;
                	LOG.trace("New connection state CS_SERVER_SESSION_TICKET");
                }

                sendChangeCipherSpecMessage();
                sendFinishedMessage();
                this.connection_state = CS_SERVER_FINISHED;
            	LOG.trace("New connection state CS_SERVER_FINISHED");

                completeHandshake();
                break;
            }
            default:
                throw new TlsFatalAlert(AlertDescription.unexpected_message);
            }
            break;
        }

        case HandshakeType.certificate_request:
        case HandshakeType.certificate_status:
        case HandshakeType.certificate_url:
        case HandshakeType.encrypted_extensions:
        case HandshakeType.end_of_early_data:
        case HandshakeType.hello_request:
        case HandshakeType.hello_verify_request:
        case HandshakeType.key_update:
        case HandshakeType.message_hash:
        case HandshakeType.new_session_ticket:
        case HandshakeType.server_hello:
        case HandshakeType.server_hello_done:
        case HandshakeType.server_key_exchange:
        default:
            throw new TlsFatalAlert(AlertDescription.unexpected_message);
        }
    }

    protected void handleAlertWarningMessage(short alertDescription)
        throws IOException
    {
        /*
         * SSL 3.0 If the server has sent a certificate request Message, the client must send
         * either the certificate message or a no_certificate alert.
         */
        if (AlertDescription.no_certificate == alertDescription && null != certificateRequest
            && TlsUtils.isSSL(tlsServerContext))
        {
            switch (this.connection_state)
            {
            case CS_SERVER_HELLO_DONE:
            {
                tlsServer.processClientSupplementalData(null);
                // NB: Fall through to next case label
            }
            case CS_CLIENT_SUPPLEMENTAL_DATA:
            {
                notifyClientCertificate(Certificate.EMPTY_CHAIN);
                this.connection_state = CS_CLIENT_CERTIFICATE;
            	LOG.trace("New connection state CS_CLIENT_CERTIFICATE");
                return;
            }
            }
        }

        super.handleAlertWarningMessage(alertDescription);
    }

    protected void notifyClientCertificate(Certificate clientCertificate)
        throws IOException
    {
        if (null == certificateRequest)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        TlsUtils.processClientCertificate(tlsServerContext, clientCertificate, keyExchange, tlsServer);
    }

    protected void receive13ClientCertificate(ByteArrayInputStream buf)
        throws IOException
    {
        // TODO[tls13]
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void receive13ClientCertificateVerify(ByteArrayInputStream buf)
        throws IOException
    {
        // TODO[tls13]
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void receive13ClientFinished(ByteArrayInputStream buf)
        throws IOException
    {
        // TODO[tls13]
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void receive13ClientHelloRetry(ByteArrayInputStream buf)
        throws IOException
    {
        // TODO[tls13]
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void receive13ClientKeyUpdate(ByteArrayInputStream buf)
        throws IOException
    {
        // TODO[tls13]
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void receiveCertificateMessage(ByteArrayInputStream buf)
        throws IOException
    {
    	LOG.debug("Receive CertificateMessage");
        Certificate clientCertificate = Certificate.parse(tlsServerContext, buf, null);

        assertEmpty(buf);

        notifyClientCertificate(clientCertificate);
    }

    protected void receiveCertificateVerifyMessage(ByteArrayInputStream buf)
        throws IOException
    {
    	LOG.debug("Receive CertificateVerifyMessage");
        DigitallySigned certificateVerify = DigitallySigned.parse(tlsServerContext, buf);

        assertEmpty(buf);

        TlsUtils.verifyCertificateVerifyClient(tlsServerContext, certificateRequest, certificateVerify, handshakeHash);

        this.handshakeHash = handshakeHash.stopTracking();
    }

    protected void receiveClientHelloMessage(ByteArrayInputStream buf)
        throws IOException
    {
    	LOG.debug("Receive ClientHelloMessage");
        ClientHello clientHello = ClientHello.parse(buf, null);
        ProtocolVersion legacy_version = clientHello.getVersion();
        LOG.debug("ClientVersion [{}]", legacy_version);
        
        /*
         * TODO RFC 5077 3.4. If a ticket is presented by the client, the server MUST NOT attempt to
         * use the Session ID in the ClientHello for stateful session resumption.
         */
        byte[] sessionID = clientHello.getSessionID();
        
        TlsSession sessionToResume = tlsServer.getSessionToResume(sessionID);
        if (sessionToResume != null && sessionToResume.isResumable())
        {
            SessionParameters sessionParameters = sessionToResume.exportSessionParameters();
            if(sessionParameters != null && legacy_version.equals(sessionParameters.getNegotiatedVersion())) 
            {
                this.tlsSession = sessionToResume;
                this.sessionParameters = sessionParameters;
                tlsServerContext.getSecurityParametersHandshake().masterSecret = getContext().getCrypto().adoptSecret(sessionParameters.getMasterSecret());
                
                if(!tlsSession.isResumable()) {
                	resetCurrentSession();
                	tlsServerContext.getSecurityParametersHandshake().clear();
                }
        	}
        }

        this.offeredCipherSuites = clientHello.getCipherSuites();
        LOG.debug("Offered CipherSuites [{}]", offeredCipherSuites);

        /*
         * RFC 5246 7.4.1.2. If the session_id field is not empty (implying a session
         * resumption request), this vector MUST include at least the cipher_suite from that
         * session.
         */
        if (sessionID.length > 0 && this.sessionParameters != null)
        {
            if (!Arrays.contains(this.offeredCipherSuites, sessionParameters.getCipherSuite()))
            {
                resetCurrentSession();
            }
        }

        /*
         * TODO RFC 3546 2.3 If [...] the older session is resumed, then the server MUST ignore
         * extensions appearing in the client hello, and send a server hello containing no
         * extensions.
         */
        this.clientExtensions = clientHello.getExtensions();


 
        SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();

        if (!legacy_version.isTLS())
        {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
        }

        tlsServerContext.setRSAPreMasterSecretVersion(legacy_version);

        tlsServerContext.setClientSupportedVersions(
            TlsExtensionsUtils.getSupportedVersionsExtensionClient(clientExtensions));

        ProtocolVersion client_version = legacy_version;
        if (null == tlsServerContext.getClientSupportedVersions())
        {
            if (client_version.isLaterVersionOf(ProtocolVersion.TLSv12))
            {
                client_version = ProtocolVersion.TLSv12;
            }

            tlsServerContext.setClientSupportedVersions(client_version.downTo(ProtocolVersion.SSLv3));
        }
        else
        {
            client_version = ProtocolVersion.getLatestTLS(tlsServerContext.getClientSupportedVersions());
        }

        if (!ProtocolVersion.SERVER_EARLIEST_SUPPORTED_TLS.isEqualOrEarlierVersionOf(client_version))
        {
            throw new TlsFatalAlert(AlertDescription.protocol_version);
        }

        if (ProtocolVersion.contains(tlsServerContext.getClientSupportedVersions(), ProtocolVersion.SSLv3))
        {
            // TODO[tls13] Prevent offering SSLv3 AND TLSv13?
            this.recordStream.setWriteVersion(ProtocolVersion.SSLv3);
        }
        else
        {
            // TODO[tls13] For subsequent ClientHello messages (of a TLSv13 handshake) don't do this!
            this.recordStream.setWriteVersion(ProtocolVersion.TLSv10);
        }

        if (securityParameters.isRenegotiating())
        {
            // Check that this is either the originally offered version or the negotiated version
            if (!client_version.equals(tlsServerContext.getClientVersion())
                && !client_version.equals(tlsServerContext.getServerVersion()))
            {
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);
            }
        }
        else
        {
            tlsServerContext.setClientVersion(client_version);
        }

        tlsServer.notifyClientVersion(tlsServerContext.getClientVersion());

        securityParameters.clientRandom = clientHello.getRandom();

        if (sessionID.length > 0 && this.sessionParameters != null)
        {
            tlsServer.notifyFallback(sessionParameters.getCipherSuite() == CipherSuite.TLS_FALLBACK_SCSV);
        	tlsServer.notifyOfferedCipherSuites(new int[] {sessionParameters.getCipherSuite()});
        }
        else {
            tlsServer.notifyFallback(Arrays.contains(offeredCipherSuites, CipherSuite.TLS_FALLBACK_SCSV));
        	tlsServer.notifyOfferedCipherSuites(offeredCipherSuites);
        }

        byte[] renegExtData = TlsUtils.getExtensionData(clientExtensions, EXT_RenegotiationInfo);

        if (securityParameters.isRenegotiating())
        {
            /*
             * RFC 5746 3.7. Server Behavior: Secure Renegotiation
             * 
             * This text applies if the connection's "secure_renegotiation" flag is set to TRUE.
             */
            if (!securityParameters.isSecureRenegotiation())
            {
                throw new TlsFatalAlert(AlertDescription.internal_error);
            }

            /*
             * When a ClientHello is received, the server MUST verify that it does not contain the
             * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If the SCSV is present, the server MUST abort
             * the handshake.
             */
            if (Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            /*
             * The server MUST verify that the "renegotiation_info" extension is present; if it is
             * not, the server MUST abort the handshake.
             */
            if (null == renegExtData)
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }

            /*
             * The server MUST verify that the value of the "renegotiated_connection" field is equal
             * to the saved client_verify_data value; if it is not, the server MUST abort the
             * handshake.
             */
            SecurityParameters saved = tlsServerContext.getSecurityParametersConnection();
            byte[] reneg_conn_info = saved.getPeerVerifyData();

            if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(reneg_conn_info)))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
        }
        else
        {
            /*
             * RFC 5746 3.6. Server Behavior: Initial Handshake
             */

            /*
             * RFC 5746 3.4. The client MUST include either an empty "renegotiation_info" extension,
             * or the TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value in the
             * ClientHello. Including both is NOT RECOMMENDED.
             */

            /*
             * When a ClientHello is received, the server MUST check if it includes the
             * TLS_EMPTY_RENEGOTIATION_INFO_SCSV SCSV. If it does, set the secure_renegotiation flag
             * to TRUE.
             */
            if (Arrays.contains(offeredCipherSuites, CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV))
            {
                securityParameters.secureRenegotiation = true;
            }

            /*
             * The server MUST check if the "renegotiation_info" extension is included in the
             * ClientHello.
             */
            if (renegExtData != null)
            {
                /*
                 * If the extension is present, set secure_renegotiation flag to TRUE. The
                 * server MUST then verify that the length of the "renegotiated_connection"
                 * field is zero, and if it is not, MUST abort the handshake.
                 */
                securityParameters.secureRenegotiation = true;

                if (!Arrays.constantTimeAreEqual(renegExtData, createRenegotiationInfo(TlsUtils.EMPTY_BYTES)))
                {
                    throw new TlsFatalAlert(AlertDescription.handshake_failure);
                }
            }
        }

        tlsServer.notifySecureRenegotiation(securityParameters.isSecureRenegotiation());

        this.offeredExtendedMasterSecret = TlsExtensionsUtils.hasExtendedMasterSecretExtension(clientExtensions);

        if (clientExtensions != null)
        {
            // NOTE: Validates the padding extension data, if present
            TlsExtensionsUtils.getPaddingExtension(clientExtensions);

            /*
             * [jsse] RFC 6066 A server that implements this extension MUST NOT accept the
             * request to resume the session if the server_name extension contains a different name.
             */
            if (sessionID.length > 0 && this.sessionParameters != null)
            {
            	ServerNameList oldServerNameList = TlsExtensionsUtils.getServerNameExtension(sessionParameters.readClientExtensions());
            	ServerNameList serverNameList = TlsExtensionsUtils.getServerNameExtension(clientExtensions);
            	if ((oldServerNameList != null && oldServerNameList.getServerNameList() != null) && //
            			!oldServerNameList.getServerNameList().equals(serverNameList.getServerNameList()))
            	{
            		resetCurrentSession();
            	}
            }
            
            securityParameters.clientServerNames = TlsExtensionsUtils.getServerNameExtensionClient(clientExtensions);

            /*
             * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
             * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
             */
            if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(client_version))
            {
                TlsUtils.establishClientSigAlgs(securityParameters, clientExtensions);
            }

            securityParameters.clientSupportedGroups = TlsExtensionsUtils.getSupportedGroupsExtension(clientExtensions);

            tlsServer.processClientExtensions(clientExtensions);
        }
    }

    protected void receiveClientKeyExchangeMessage(ByteArrayInputStream buf)
        throws IOException
    {
    	LOG.debug("Receive ClientKeyExchangeMessage");
        keyExchange.processClientKeyExchange(buf);

        assertEmpty(buf);

        final boolean isSSL = TlsUtils.isSSL(tlsServerContext);
        if (isSSL)
        {
            // NOTE: For SSLv3 (only), master_secret needed to calculate session hash
            establishMasterSecret(tlsServerContext, keyExchange);
        }

        tlsServerContext.getSecurityParametersHandshake().sessionHash = TlsUtils.getCurrentPRFHash(handshakeHash);

        if (!isSSL)
        {
            // NOTE: For (D)TLS, session hash potentially needed for extended_master_secret
            establishMasterSecret(tlsServerContext, keyExchange);
        }

        recordStream.setPendingConnectionState(TlsUtils.initCipher(tlsServerContext));

        if (!expectCertificateVerifyMessage())
        {
            this.handshakeHash = handshakeHash.stopTracking();
        }
    }

    protected void send13ServerHelloCoda(ServerHello serverHello, boolean afterHelloRetryRequest) throws IOException
    {
        final SecurityParameters securityParameters = tlsServerContext.getSecurityParametersHandshake();

        byte[] serverHelloTranscriptHash = TlsUtils.getCurrentPRFHash(handshakeHash);

        TlsUtils.establish13PhaseHandshake(tlsServerContext, serverHelloTranscriptHash, recordStream);

        /*
         * TODO[tls13] EncryptedExtensions
         */
        this.connection_state = CS_SERVER_ENCRYPTED_EXTENSIONS;
    	LOG.trace("New connection state CS_SERVER_ENCRYPTED_EXTENSIONS");

        // CertificateRequest
        {
            this.certificateRequest = tlsServer.getCertificateRequest();
            if (null != certificateRequest)
            {
                if (!certificateRequest.hasCertificateRequestContext(TlsUtils.EMPTY_BYTES))
                {
                    throw new TlsFatalAlert(AlertDescription.internal_error);
                }

                TlsUtils.establishServerSigAlgs(securityParameters, certificateRequest);

                sendCertificateRequestMessage(certificateRequest);
                this.connection_state = CS_SERVER_CERTIFICATE_REQUEST;
            	LOG.trace("New connection state CS_SERVER_CERTIFICATE_REQUEST");
            }
        }

        /*
         * TODO[tls13] For PSK-only key exchange, there's no Certificate message.
         */

        TlsCredentialedSigner serverCredentials = TlsUtils.establish13ServerCredentials(tlsServer);
        if (null == serverCredentials)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        // Certificate
        {
            /*
             * TODO[tls13] Note that we are expecting the TlsServer implementation to take care of
             * e.g. adding optional "status_request" extension to each CertificateEntry.
             */
            /*
             * No CertificateStatus message is sent; TLS 1.3 uses per-CertificateEntry
             * "status_request" extension instead.
             */

            ByteArrayOutputStream endPointHash = new ByteArrayOutputStream();
            Certificate serverCertificate = serverCredentials.getCertificate();
            send13CertificateMessage(serverCertificate, endPointHash);
            securityParameters.tlsServerEndPoint = endPointHash.toByteArray();
            securityParameters.statusRequestVersion = 1;
            this.connection_state = CS_SERVER_CERTIFICATE;
        	LOG.trace("New connection state CS_SERVER_CERTIFICATE");
        }

        // CertificateVerify
        {
            DigitallySigned certificateVerify = TlsUtils.generate13CertificateVerify(tlsServerContext, serverCredentials,
                handshakeHash);
            send13CertificateVerifyMessage(certificateVerify);
            this.connection_state = CS_CLIENT_CERTIFICATE_VERIFY;
        	LOG.trace("New connection state CS_CLIENT_CERTIFICATE_VERIFY");
        }

        // Finished
        {
            send13FinishedMessage();
            this.connection_state = CS_SERVER_FINISHED;
        	LOG.trace("New connection state CS_SERVER_FINISHED");
        }

        this.serverFinishedTranscriptHash = TlsUtils.getCurrentPRFHash(handshakeHash);
    }

    protected void sendCertificateRequestMessage(CertificateRequest certificateRequest)
        throws IOException
    {
    	LOG.debug("Send CertificateRequestMessage");
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.certificate_request);
        certificateRequest.encode(tlsServerContext, message);
        message.send(this);
    }

    protected void sendCertificateStatusMessage(CertificateStatus certificateStatus)
        throws IOException
    {
    	LOG.debug("Send CertificateStatusMessage");
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.certificate_status);
        // TODO[tls13] Ensure this cannot happen for (D)TLS1.3+
        certificateStatus.encode(message);
        message.send(this);
    }

    protected void sendHelloRequestMessage()
        throws IOException
    {
        HandshakeMessageOutput.send(this, HandshakeType.hello_request, TlsUtils.EMPTY_BYTES);
    }

    protected void sendNewSessionTicketMessage(NewSessionTicket newSessionTicket)
        throws IOException
    {
        if (newSessionTicket == null)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.new_session_ticket);
        newSessionTicket.encode(message);
        message.send(this);
    }

    protected void sendServerHelloDoneMessage()
        throws IOException
    {
        LOG.debug("Send ServerHelloDoneMessage");
        HandshakeMessageOutput.send(this, HandshakeType.server_hello_done, TlsUtils.EMPTY_BYTES);
    }

    protected void sendServerHelloMessage(ServerHello serverHello)
        throws IOException
    {
	    LOG.debug("Send ServerHelloMessage");
        HandshakeMessageOutput message = new HandshakeMessageOutput(HandshakeType.server_hello);
        serverHello.encode(tlsServerContext, message);
        message.send(this);
    }

    protected void sendServerKeyExchangeMessage(byte[] serverKeyExchange)
        throws IOException
    {
        LOG.debug("Send ServerKeyExchangeMessage");
        HandshakeMessageOutput.send(this, HandshakeType.server_key_exchange, serverKeyExchange);
    }

    protected void skip13ClientCertificate()
        throws IOException
    {
        // TODO[tls13]
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }

    protected void skip13ClientCertificateVerify()
        throws IOException
    {
        // TODO[tls13]
        throw new TlsFatalAlert(AlertDescription.internal_error);
    }
}
