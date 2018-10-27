using System;
using System.Configuration;

namespace AZURE.API.OWTSERVICE.Models
{
    /// <summary>
    /// This object is used as a medium to allow client application to pass
    /// the Payload data to generate the Json Web Token. This information will be
    /// process by the Service Method to generated the Token. This object act as the
    /// binding contract between the client application and the Web API Service.
    /// </summary>
    public class OwtPayloadContract
    {
        // Private Claims
        private string _issuer = string.Empty;
        private string _audience = string.Empty;
       
        // Public Claims
        private string _uri = string.Empty;                 // Client Application URL.
        private string _actor = string.Empty;               // The Windows User Id such as "dshs\ferreks".
        private string _role = string.Empty;                // "Guest" or "Admin" or "Super User" etc
        private string _sid = string.Empty;                 // Session ID
        private string _name = string.Empty;                // The actual user full name like "John Doe"
        private string _employeeId = string.Empty;          // The User ID.
        private string _dns = string.Empty;                 // the DNS of the client machine use to access the application that call the service.
        private string _email = string.Empty;               // the client user email addresss.
        private string _macAddress = string.Empty;          // the Mac Address of the client user machine.
        private string _ipAddress = string.Empty;           // the IP Address of the client user machine.

        #region Private Claims Properties

        /// <summary>
        /// REQUIRED - The Full Name of the Token Issuer.
        /// </summary>
        public string Issuer
        {
            get { return this._issuer; }
            set { this._issuer = value; }
        }

        /// <summary>
        /// REQUIRED - This is the Client Application Name.
        /// </summary>
        public string Audience
        {
            get { return this._audience; }
            set { this._audience = value; }
        }

        /// <summary>
        /// AUTO DETERMINE - To be set by the service during runtime but as an option to be specified by the client.
        /// </summary>
        public DateTime NotBefore
        {
            get { return DateTime.UtcNow.ToLocalTime(); }
        }

        /// <summary>
        /// AUTO DETERMINE - The Expiration DateTime of the Token.
        /// </summary>
        public DateTime Expires
        {
            get
            {
                return DateTime.UtcNow.ToLocalTime()
                    .AddMinutes(Double.Parse(ConfigurationManager.AppSettings["OwtExpiresTime"]));
            }
        }

        /// <summary>
        /// AUTO DETERMINE - To be set by the service during runtime but as an option to be specified by the client.
        /// </summary>
        public DateTime IssuedAt
        {
            get { return DateTime.UtcNow.ToLocalTime(); }
        }

        #endregion

        #region Public Claims Properties are Optional Values.

        /// <summary>
        /// Client Application URL.
        /// </summary>
        public string URI
        {
            get { return this._uri; }
            set { this._uri = value; }
        }
     
        /// <summary>
        /// The Windows User Id such as "dshs\ferreks". This map to the Actor property in the ClaimTypes.
        /// </summary>
        public string Actor
        {
            get { return this._actor; }
            set { this._actor = value; }
        }

        /// <summary>
        /// "Guest" or "Admin" or "Super User". Can be further extendable to a list type.
        /// This Map to the Role property in the ClaimTypes.
        /// </summary>
        public string Role
        {
            get { return this._role; }
            set { this._role = value; }
        }

        /// <summary>
        /// User Session ID determine from the Client Application at Logon.
        /// This map to the Sid property in the ClaimTypes.
        /// </summary>
        public string SID
        {
            get { return this._sid; }
            set { this._sid = value; }
        }

        /// <summary>
        /// The actual user full name like "John Doe". Determine by the application after successful sign on.
        /// This map to the Name property in the ClaimTypes.
        /// </summary>
        public string Name
        {
            get { return this._name; }
            set { this._name = value; }
        }

        /// <summary>
        /// This is the ID of the user. This map to the NameIdentifier property in the ClaimTypes.
        /// 
        /// </summary>
        public string EmployeeId
        {
            get { return this._employeeId; }
            set { this._employeeId = value; }
        }

        /// <summary>
        /// The DNS of the client machine use to access the application that call the service.
        /// This map to the Dns property in the ClaimTypes. 
        /// </summary>
        public string DNS
        {
            get { return this._dns; }
            set { this._dns = value; }
        }

        /// <summary>
        /// The client user email addresss. This determines from the Client Application. 
        /// This map to the Email property of the ClaimTypes. 
        /// </summary>
        public string Email
        {
            get { return this._email; }
            set { this._email = value; }
        }

        /// <summary>
        /// The Mac Address of the client user machine map to the Hash property in the ClaimTypes.
        /// </summary>
        public string MacAddress
        {
            get { return this._macAddress; }
            set { this._macAddress = value; }
        }

        /// <summary>
        /// The IP Address of the client user machine map to the locality property in the ClaimTypes.
        /// </summary>
        public string IpAddress
        {
            get { return this._ipAddress; }
            set { this._ipAddress = value; }
        }
        #endregion

        #region Overrided method 

        /// <summary>
        /// This is an override method of the base object to facilate
        /// the output of our objects with useful information.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            string retString = string.Empty;

            retString = $"ISSUER: {Issuer} | AUDIENCE: {Audience} | NOT_BEFORE {NotBefore} | EXPIRES {Expires} | ISSUED_AT {IssuedAt} ";
            retString = retString + $"| URI: {URI} | ACTOR: {Actor} | ROLE: {Role} | SID: {SID} | DNS: {DNS} ";
            retString = retString + $"| NAME: {Name} | EmployeeId: {EmployeeId} | Email: {Email} | MacAddress: {MacAddress} | IpAddress: {IpAddress} ";

            return retString;
        }

        #endregion
    }
}