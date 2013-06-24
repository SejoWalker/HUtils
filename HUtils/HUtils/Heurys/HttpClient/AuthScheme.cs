namespace Heurys.HttpClient
{
    using System;

    internal class AuthScheme
    {
        private string _password;
        private string _realm;
        private int _scheme;
        private string _user;

        public AuthScheme(int scheme, string realm, string user, string password)
        {
            this._scheme = scheme;
            this._realm = realm;
            this._user = user;
            this._password = password;
        }

        public string Password
        {
            get
            {
                return this._password;
            }
        }

        public string Realm
        {
            get
            {
                return this._realm;
            }
        }

        public int Scheme
        {
            get
            {
                return this._scheme;
            }
        }

        public string User
        {
            get
            {
                return this._user;
            }
        }
    }
}

