db.book.createIndex({ title: "text" }, { name: "book_text" });
db.movie.createIndex({ title: "text" }, { name: "movie_text" });
db.tvshow.createIndex({ title: "text" }, { name: "tvshow_text" });
db.videogame.createIndex({ title: "text" }, { name: "videogame_text" });
