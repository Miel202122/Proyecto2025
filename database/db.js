const mysql=require('mysql');
const mysqlConnection = mysql.createConnection({
    host: "mysql-mielproyecto.alwaysdata.net",
    user: "410125",
    password: "Miel123",
    database: "mielproyecto_dbmiel",
});
mysqlConnection.connect((error)=>{
    if(error){
        console.log('Error en la conecxion: '+ error);
        return;
    }
    console.log('Base de datos conectada.')
});

module.exports= mysqlConnection;