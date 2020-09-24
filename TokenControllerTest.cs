using AuthorizationService;
using AuthorizationService.Controllers;
using AuthorizationService.Provider;
using AuthorizationService.Repository;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace Authorization.Testing
{
    public class TokenControllerTest
    {
        private Dictionary<string, string> dc = new Dictionary<string, string>()
        {
               {"Sujoy","Basak"},
               {"Supriya","Sinha"},
               {"Aman","Bharti"},
               {"Shubham","Debnath"}
        };

        [TestCase("Sujoy","Basak")]
        [TestCase("Aman","Bharti")]
        public void TokenGenarationProviderTest(string name, string pass)
        {
            
            Mock<IConfiguration> config = new Mock<IConfiguration>();
            config.Setup(p=>p["Jwt:Key"]).Returns("ThisismySecretKey");
            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);
            AuthProvider cp = new AuthProvider(mock.Object);
            Authenticate user = new Authenticate()
            {
                Name = name,
                Password = pass
            };
            string result = cp.GenerateJSONWebToken(user,config.Object);
            Assert.IsNotNull(result);
        }

        [TestCase("Sujoy", "Basak")]
        public void CredentialsProviderTest(string name, string pass)
        {

            //Mock<IConfiguration> config = new Mock<IConfiguration>();
            //config.Setup(p => p["Jwt:Key"]).Returns("ThisismySecretKey");
            Mock<ICredentialsRepo> mock = new Mock<ICredentialsRepo>();
            mock.Setup(p => p.GetCredentials()).Returns(dc);
            AuthProvider cp = new AuthProvider(mock.Object);
            Authenticate user = new Authenticate()
            {
                Name = name,
                Password = pass
            };
            Authenticate result = cp.AuthenticateUser(user);
            Assert.IsNotNull(result);
        }

    }
}