namespace Heurys.HttpClient
{
    //using GeneXus.Configuration;
    //using log4net;
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.IO;
    using System.Net;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Web;
    using System.Web.Services.Protocols;

    public class HttpClient : IHttpClient
    {
        private ArrayList _authCollection = new ArrayList();
        private ArrayList _authProxyCollection = new ArrayList();
        private List<Cookie> _cookies = new List<Cookie>();
        private string _baseUrl = "";
        public const int _Basic = 0;
        private X509CertificateCollection _certificateCollection = new X509CertificateCollection();
        public const int _Digest = 1;
        private Encoding _encoding;
        private short _errCode;
        private string _errDescription = "";
        private NameValueCollection _formVars = new NameValueCollection();
        private NameValueCollection _headers = new NameValueCollection();
        private string _host = "";
        public const int _Kerberos = 3;
        public const int _NTLM = 2;
        private int _port;
        private string _proxyHost = "";
        private WebProxy _proxyObject;
        private int _proxyPort;
        private Stream _receiveStream;
        private string _scheme = "http://";
        private Stream _sendStream;
        private short _statusCode;
        private string _statusDescription;
        private int _timeout = 0x7530;
        private string _url = "";
        //private static readonly ILog log = LogManager.GetLogger("Heurys.HttpClient.HttpClient");

        public HttpClient()
        {
            try
            {
                this._proxyObject = WebProxy.GetDefaultProxy();
                if ((this._proxyObject != null) && (this._proxyObject.Address != null))
                {
                    this._proxyHost = this._proxyObject.Address.Host;
                    this._proxyPort = this._proxyObject.Address.Port;
                }
            }
            catch
            {
                this._proxyObject = null;
            }
        }

        public void AddAuthentication(int scheme, string realm, string user, string password)
        {
            if ((scheme >= 0) && (scheme <= 3))
            {
                this._authCollection.Add(new AuthScheme(scheme, realm, user, password));
            }
        }

        public void AddCertificate(string cert)
        {
            Regex regex = new Regex(@"(\s*\((?'fName'\S+)\s*\,\s*(?'pass'\S+)\s*\)|(?'fName'\S+))");
            foreach (Match match in regex.Matches(cert))
            {
                this.AddCertificate(match.Groups["fName"].Value, match.Groups["pass"].Value);
            }
        }

        public void AddCertificate(string file, string pass)
        {
            X509Certificate certificate;
            if ((pass == null) || (pass.Trim().Length == 0))
            {
                certificate = X509Certificate.CreateFromCertFile(file);
            }
            else
            {
                certificate = new X509Certificate(file, pass);
            }
            this._certificateCollection.Add(certificate);
        }

        public void AddFile(string s)
        {
            FileStream stream = new FileStream(s, FileMode.Open, FileAccess.Read);
            byte[] buffer = new byte[0x400];
            for (int i = stream.Read(buffer, 0, 0x400); i > 0; i = stream.Read(buffer, 0, 0x400))
            {
                this.SendStream.Write(buffer, 0, i);
            }
            stream.Close();
        }

        public void AddHeader(string name, string value)
        {
            this._headers.Set(name.ToUpper(), value);
        }

        public void AddProxyAuthentication(int scheme, string realm, string user, string password)
        {
            if ((scheme >= 0) && (scheme <= 3))
            {
                this._authProxyCollection.Add(new AuthScheme(scheme, realm, user, password));
            }
        }

        public void AddString(string s)
        {
            StreamWriter writer = new StreamWriter(this.SendStream);
            writer.Write(s);
            writer.Flush();
        }

        public void AddVariable(string name, string value)
        {
            this._formVars.Add(name, value);
            this.AddHeader("content-type", "application/x-www-form-urlencoded");
        }

        private HttpWebRequest buildRequest(string method, string name, CookieContainer cookies)
        {
            //if (log.IsDebugEnabled)
            //{
            //    log.Debug("Start buildRequest: method '" + method + "', name '" + name + "'");
            //}
            byte[] buffer = new byte[0x400];
            string requestUriString = this._url + "/" + name;
            if (string.IsNullOrEmpty(this._url))
            {
                requestUriString = name;
            }
            HttpWebRequest req = (HttpWebRequest) WebRequest.Create(requestUriString);
            req.Credentials = this.getCredentialCache(req.RequestUri, this._authCollection);
            req.CookieContainer = cookies;
            foreach (X509Certificate certificate in this._certificateCollection)
            {
                req.ClientCertificates.Add(certificate);
            }
            req.Method = method;
            req.Timeout = this._timeout;
            this.setHttpVersion(req);
            WebProxy proxy = this.getProxy(this._proxyHost, this._proxyPort, this._authProxyCollection);
            if (proxy != null)
            {
                req.Proxy = proxy;
            }
            this.setHeaders(req);
            if (method.ToUpper() != "GET")
            {
                Stream requestStream = req.GetRequestStream();
                this.sendVariables(requestStream);
                this.SendStream.Seek(0L, SeekOrigin.Begin);
                int count = this.SendStream.Read(buffer, 0, 0x400);
                //if (log.IsDebugEnabled)
                //{
                //    log.Debug("Start SendStream.Read: BytesRead " + count);
                //}
                while (count > 0)
                {
                    //if (log.IsDebugEnabled)
                    //{
                    //    log.Debug(string.Concat(new object[] { "reqStream.Write: Buffer.length ", buffer.Length, ",'", Encoding.UTF8.GetString(buffer, 0, buffer.Length), "'" }));
                    //}
                    requestStream.Write(buffer, 0, count);
                    count = this.SendStream.Read(buffer, 0, 0x400);
                }
                requestStream.Close();
            }
            return req;
        }

        private void buildUrl()
        {
            string str;
            if (this._port == 0)
            {
                str = "";
            }
            else
            {
                str = ":" + this._port.ToString();
            }
            string str2 = this._host;
            if (str2.StartsWith("//"))
            {
                str2 = str2.Substring(2, str2.Length - 2);
            }
            if (str2.EndsWith("/"))
            {
                str2 = str2.Substring(0, str2.Length - 1);
            }
            string str3 = this._baseUrl;
            if (str3.StartsWith("/"))
            {
                str3 = str3.Substring(1, str3.Length - 1);
            }
            this._url = this._scheme + str2 + str + "/" + str3;
            if (this._url.EndsWith("/"))
            {
                this._url = this._url.Substring(0, this._url.Length - 1);
            }
        }

        private string buildVariableToSend(string key, string value)
        {
            return (System.Web.HttpUtility.UrlEncode(key) + "=" + System.Web.HttpUtility.UrlEncode(value) + "&");
        }

        public void ClearFiles()
        {
            this.ClearSendStream();
        }

        public void ClearHeaders()
        {
            this._headers.Clear();
        }

        private void ClearSendStream()
        {
            this.SendStream = null;
        }

        public void ClearStrings()
        {
            this.ClearSendStream();
        }

        public void ClearVariables()
        {
            this._formVars.Clear();
        }

        public void ConfigureHttpClientProtocol(string name, SoapHttpClientProtocol httpC)
        {
            string uriString = this._url + "/" + name;
            httpC.Url = uriString;
            httpC.Credentials = this.getCredentialCache(new Uri(uriString), this._authCollection);
            WebProxy proxy = this.getProxy(this._proxyHost, this._proxyPort, this._authProxyCollection);
            if (proxy != null)
            {
                httpC.Proxy = proxy;
            }
            foreach (X509Certificate certificate in this._certificateCollection)
            {
                httpC.ClientCertificates.Add(certificate);
            }
            httpC.Timeout = this._timeout;
        }

        public void SetCookies(List<CookieItem> lista)
        {
            _cookies.Clear();
            foreach (CookieItem ci in lista)
            {
                _cookies.Add(ci.Cookie);
            }
        }

        public List<CookieItem> GetCookies()
        {
            List<CookieItem> lista = new List<CookieItem>();
            foreach (Cookie c in _cookies)
            {
                CookieItem ci = new CookieItem();
                ci.Cookie = c;
                lista.Add(ci);
            }
            return lista;
        }

        public void Execute(string method, string name)
        {
            HttpWebResponse response;
            byte[] buffer = new byte[0x400];
            this._errCode = 0;
            this._errDescription = "";
            CookieContainer cookies = new CookieContainer();
            foreach (Object co in _cookies)
            {
                Cookie c = co as Cookie;
                cookies.Add(c);
            }
            //if (log.IsDebugEnabled)
            //{
            //    log.Debug("Start Execute: method '" + method + "', name '" + name + "'");
            //}
            try
            {
                response = (HttpWebResponse) this.buildRequest(method, name, cookies).GetResponse();
            }
            catch (WebException exception)
            {
                //if (log.IsErrorEnabled)
                //{
                  //  log.Error("Error Execute", exception);
               // }
                this._errCode = 1;
                this._errDescription = exception.Message;
                response = (HttpWebResponse) exception.Response;
                if (response == null)
                {
                    return;
                }
            }
            //if (log.IsDebugEnabled)
            //{
              //  log.Debug("Reading response...");
            //}
            this._receiveStream = new MemoryStream();
            _cookies.Clear();
            foreach (Cookie c in response.Cookies)
            {
                _cookies.Add(c);
            }
            Stream responseStream = response.GetResponseStream();
            buffer = new byte[0x400];
            int bytesRead = responseStream.Read(buffer, 0, 0x400);
            //if (log.IsDebugEnabled)
           // {
           //     log.Debug("BytesRead " + bytesRead);
           // }
            bool flag = false;
            while (bytesRead > 0)
            {
                if (!flag)
                {
                    this._encoding = this.findEncoding(buffer, bytesRead);
                    flag = true;
                }
                this._receiveStream.Write(buffer, 0, bytesRead);
                bytesRead = responseStream.Read(buffer, 0, 0x400);
               // if (log.IsDebugEnabled)
               // {
              //      log.Debug("BytesRead " + bytesRead);
               // }
            }
            this._receiveStream.Seek(0L, SeekOrigin.Begin);
            responseStream.Close();
            this._statusCode = (short) response.StatusCode;
            this._statusDescription = response.StatusDescription;
            response.Close();
            this.ClearSendStream();
            //if (log.IsDebugEnabled)
            //{
            //    log.Debug("_responseString " + this.ToString());
            //}
        }

        private Encoding findEncoding(byte[] Buffer, int BytesRead)
        {
            string str = Encoding.UTF8.GetString(Buffer, 0, BytesRead);
            int index = str.ToLower().IndexOf("encoding");
            if (index >= 0)
            {
                int num3;
                int num2 = str.IndexOf("\"", index);
                if (num2 >= 0)
                {
                    num3 = str.IndexOf("\"", (int) (num2 + 1));
                }
                else
                {
                    num3 = num2 + 1;
                }
                try
                {
                    return Encoding.GetEncoding(str.Substring(num2 + 1, num3 - (num2 + 1)));
                }
                catch
                {
                    return Encoding.UTF8;
                }
            }
            return Encoding.UTF8;
        }

        public string get_ProxyHost()
        {
            return this._proxyHost;
        }

        public int get_ProxyPort()
        {
            return this._proxyPort;
        }

        public short getBasic()
        {
            return 0;
        }

        private ICredentials getCredentialCache(Uri URI, ArrayList authenticationCollection)
        {
            CredentialCache cache = new CredentialCache();
            for (int i = 0; i < authenticationCollection.Count; i++)
            {
                string str;
                AuthScheme scheme = (AuthScheme) authenticationCollection[i];
                switch (scheme.Scheme)
                {
                    case 0:
                        str = "Basic";
                        break;

                    case 1:
                        str = "Digest";
                        break;

                    case 2:
                        str = "NTLM";
                        break;

                    case 3:
                        str = "Negotiate";
                        break;

                    default:
                    {
                        continue;
                    }
                }
                try
                {
                    if (((str == "NTLM") || (str == "Negotiate")) && ((scheme.User.Trim().Length == 0) && (scheme.Password.Trim().Length == 0)))
                    {
                        return CredentialCache.DefaultCredentials;
                    }
                    if (str != "Basic")
                    {
                        cache.Add(URI, str, new NetworkCredential(scheme.User, scheme.Password, scheme.Realm));
                    }
                    else
                    {
                        cache.Add(URI, str, new NetworkCredential(scheme.User, scheme.Password));
                    }
                }
                catch (ArgumentException)
                {
                }
            }
            return cache;
        }

        public short getDigest()
        {
            return 1;
        }

        public string GetHeader(string name)
        {
            return this._headers.Get(name);
        }

        public void GetHeader(string name, out DateTime value)
        {
            value = Convert.ToDateTime(this.GetHeader(name));
        }

        public void GetHeader(string name, out double value)
        {
            value = Convert.ToDouble(this.GetHeader(name));
        }

        public void GetHeader(string name, out short value)
        {
            value = Convert.ToInt16(this.GetHeader(name));
        }

        public void GetHeader(string name, out int value)
        {
            value = Convert.ToInt32(this.GetHeader(name));
        }

        public void GetHeader(string name, out long value)
        {
            value = Convert.ToInt64(this.GetHeader(name));
        }

        public void GetHeader(string name, out string value)
        {
            value = this.GetHeader(name);
        }

        public short getNTLM()
        {
            return 2;
        }

        private WebProxy getProxy(string proxyHost, int proxyPort, ArrayList authenticationCollection)
        {
            if (proxyHost.Length <= 0)
            {
                return null;
            }
            WebProxy proxy = new WebProxy(proxyHost, proxyPort);
            if (this._proxyObject != null)
            {
                proxy.BypassProxyOnLocal = this._proxyObject.BypassProxyOnLocal;
                proxy.BypassList = this._proxyObject.BypassList;
            }
            proxy.Credentials = this.getCredentialCache(proxy.Address, authenticationCollection);
            return proxy;
        }

        private void sendVariables(Stream reqStream)
        {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < this._formVars.Count; i++)
            {
                if (this._formVars.Keys[i] != null)
                {
                    builder.Append(this.buildVariableToSend(this._formVars.Keys[i], this._formVars[i]));
                }
            }
            if (this._formVars.Count > 0)
            {
                builder.Remove(builder.Length - 1, 1);
            }
            StreamWriter writer = new StreamWriter(reqStream);
            writer.Write(builder.ToString());
            writer.Flush();
        }

        public void set_ProxyHost(string host)
        {
            this._proxyHost = host;
        }

        public void set_ProxyPort(int port)
        {
            this._proxyPort = port;
        }

        private void setHeaders(HttpWebRequest req)
        {
            string str3;
            for (int i = 0; i < this._headers.Count; i++)
            {
                string name = this._headers.Keys[i];
                string str4 = name.ToUpper();
                if (str4 == null)
                {
                    goto Label_007E;
                }
                if (!(str4 == "CONNECTION"))
                {
                    if (str4 == "CONTENT-TYPE")
                    {
                        goto Label_006A;
                    }
                    goto Label_007E;
                }
                if (this._headers[i].ToUpper() == "CLOSE")
                {
                    req.KeepAlive = false;
                }
                continue;
            Label_006A:
                req.ContentType = this._headers[i];
                continue;
            Label_007E:
                req.Headers.Add(name, this._headers[i]);
            }
            //if (Config.GetValueOf("HttpClientConnection", out str3))
            //{
                str3 = "Close"; // RMS
                if (str3 == "Close")
                {
                    req.KeepAlive = false;
                }
                else
                {
                    req.KeepAlive = true;
                }
            //}
        }

        private void setHttpVersion(HttpWebRequest req)
        {
            //string str;
            // rms
            //if (Config.GetValueOf("HttpClientHttpVersion", out str))
            //{
            /*
                if (str == "1.0")
                {
                    req.ProtocolVersion = HttpVersion.Version10;
                }
                else
                {
                    req.ProtocolVersion = HttpVersion.Version11;
                }
             */ 
            //}
            //else
            //{
                req.ProtocolVersion = HttpVersion.Version11;
            //}
        }

        public void ToFile(string fileName)
        {
            string path = fileName;
            if ((HttpContext.Current != null) && (fileName.IndexOfAny(new char[] { '\\', ':' }) == -1))
            {
                path = HttpContext.Current.Request.PhysicalApplicationPath + fileName;
            }
            FileStream stream = new FileStream(path, FileMode.Create, FileAccess.Write);
            this.ReceiveStream.Seek(0L, SeekOrigin.Begin);
            byte[] buffer = new byte[0x400];
            for (int i = this.ReceiveStream.Read(buffer, 0, 0x400); i > 0; i = this.ReceiveStream.Read(buffer, 0, 0x400))
            {
                stream.Write(buffer, 0, i);
            }
            this.ReceiveStream.Seek(0L, SeekOrigin.Begin);
            stream.Close();
        }

        public override string ToString()
        {
            if (this._encoding == null)
            {
                this._encoding = Encoding.UTF8;
            }
            this.ReceiveStream.Seek(0L, SeekOrigin.Begin);
            byte[] buffer = new byte[0x400];
            int count = this.ReceiveStream.Read(buffer, 0, 0x400);
            StringBuilder builder = new StringBuilder("");
            while (count > 0)
            {
                builder.Append(this._encoding.GetString(buffer, 0, count));
                count = this.ReceiveStream.Read(buffer, 0, 0x400);
            }
            this.ReceiveStream.Seek(0L, SeekOrigin.Begin);
            return builder.ToString();
        }

        public string BaseURL
        {
            get
            {
                return this._baseUrl;
            }
            set
            {
                this._baseUrl = value;
                this.buildUrl();
            }
        }

        public short Basic
        {
            get
            {
                return 0;
            }
        }

        public short Digest
        {
            get
            {
                return 1;
            }
        }

        public short ErrCode
        {
            get
            {
                return this._errCode;
            }
        }

        public string ErrDescription
        {
            get
            {
                return this._errDescription;
            }
        }

        public string Host
        {
            get
            {
                return this._host;
            }
            set
            {
                this._host = value;
                this.buildUrl();
            }
        }

        public short Kerberos
        {
            get
            {
                return 3;
            }
        }

        public short NTLM
        {
            get
            {
                return 2;
            }
        }

        public int Port
        {
            get
            {
                return this._port;
            }
            set
            {
                this._port = value;
                this.buildUrl();
            }
        }

        public string ProxyServerHost
        {
            get
            {
                return this._proxyHost;
            }
            set
            {
                this._proxyHost = value;
            }
        }

        public int ProxyServerPort
        {
            get
            {
                return this._proxyPort;
            }
            set
            {
                this._proxyPort = value;
            }
        }

        public string ReasonLine
        {
            get
            {
                return this._statusDescription;
            }
        }

        public Stream ReceiveStream
        {
            get
            {
                if (this._receiveStream == null)
                {
                    this._receiveStream = new MemoryStream();
                }
                return this._receiveStream;
            }
        }

        public int Secure
        {
            get
            {
                if (!(this._scheme == "https://"))
                {
                    return 0;
                }
                return 1;
            }
            set
            {
                if (value == 1)
                {
                    this._scheme = "https://";
                }
                else
                {
                    this._scheme = "http://";
                }
                this.buildUrl();
            }
        }

        public Stream SendStream
        {
            get
            {
                if (this._sendStream == null)
                {
                    this._sendStream = new MemoryStream();
                }
                return this._sendStream;
            }
            set
            {
                this._sendStream = value;
            }
        }

        public short StatusCode
        {
            get
            {
                return this._statusCode;
            }
        }

        public int Timeout
        {
            get
            {
                return (this._timeout / 0x3e8);
            }
            set
            {
                if (value == 0)
                {
                    this._timeout = 0x36ee80;
                }
                else
                {
                    this._timeout = value * 0x3e8;
                }
            }
        }

        public string Url
        {
            get
            {
                return this._url;
            }
            set
            {
                this._url = value;
            }
        }
    }
}

