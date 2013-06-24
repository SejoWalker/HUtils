namespace Heurys.HttpClient
{
    using System.IO;

    public interface IHttpClient
    {
        Stream ReceiveStream { get; }

        Stream SendStream { get; }
    }
}

