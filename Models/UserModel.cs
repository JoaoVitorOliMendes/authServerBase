using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Bson;

namespace authserver.Models
{
    public class UserModel
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }
        [BsonElement("Name")]
        public string Name { get; set; }
        [BsonElement("Surname")]
        public string Surname { get; set; }
        [BsonElement("Email")]
        public string Email { get; set; }
        [BsonElement("Password")]
        public string Password { get; set; }
        [BsonElement("EmailConfirmed")]
        public bool EmailConfirmed { get; set; }

    }
}
