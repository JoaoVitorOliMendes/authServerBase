using authserver.Models;
using MongoDB.Driver;

namespace authserver.Services
{
    public class UserService
    {
        public IMongoCollection<UserModel> users;

        public UserService(IConfiguration configuration)
        {
            var client = new MongoClient(configuration.GetConnectionString("MongoDB"));
            var database = client.GetDatabase("elx-auth");
            users = database.GetCollection<UserModel>("users");
        }

        public List<UserModel> GetUsers() => users.Find(user => true).ToList();
        public UserModel GetUser(string id) => users.Find(user => user.Id == id).FirstOrDefault();
        public bool CreateUser(UserModel user)
        {
            try
            {
                users.InsertOne(user);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return false;
            }
        }
        public UserModel GetUserByEmail(string email) => users.Find(user => user.Email == email).FirstOrDefault();
    }
}
