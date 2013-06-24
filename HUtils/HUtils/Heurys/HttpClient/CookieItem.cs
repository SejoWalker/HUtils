using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Web;

namespace Heurys.HttpClient
{
	public class CookieItem 
	{
        private Cookie _cookie = new Cookie();

        public Cookie Cookie
        {
            get { return _cookie; }
            set { _cookie = value; }
        }

        public string Name
        {
            get { return _cookie.Name; }
            set { _cookie.Name = value; }
        }

        public string Value
        {
            get { return _cookie.Value; }
            set { _cookie.Value = value; }
        }

        public string Domain
        {
            get { return _cookie.Domain; }
            set { _cookie.Domain = value; }
        }

        public string Path
        {
            get { return _cookie.Path; }
            set { _cookie.Path = value; }
        }

        public string Port
        {
            get { return _cookie.Port; }
            set { _cookie.Port = value; }
        }

        public bool Expired
        {
            get { return _cookie.Expired; }
            set { _cookie.Expired = value; }
        }

        public DateTime Expires
        {
            get { return _cookie.Expires; }
            set { _cookie.Expires = value; }
        }

	}
}
