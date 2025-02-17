<?php 
session_start();
include('connect.php');

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
     <link href="https://fonts.googleapis.com/css2?family=Chewy&family=Open+Sans:ital,wght@0,300..800;1,300..800&family=Roboto:ital,wght@0,100;0,300;0,400;0,500;0,700;0,900;1,100;1,300;1,400;1,500;1,700;1,900&display=swap" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Chewy&family=Roboto:ital,wght@0,100;0,300;0,400;0,500;0,700;0,900;1,100;1,300;1,400;1,500;1,700;1,900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
    <title>Larawang Munti</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: Arial, sans-serif;
            background-color:  #0d1319;
            color: #333;

        }

        header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background-color: #2c3e50;
            padding: 15px 30px;
            color: white;
        }

        .logo {
            font-size: 40px;
            font-family: "Chewy", system-ui;
            font-weight: 400;
        }

        nav {
            margin-left: auto;
        }

        nav button {
            background-color: #2980b9;
            color: white;
            border: none;
            padding: 10px 20px;
            margin: 0 5px;
            cursor: pointer;
            font-size: 16px;
            border-radius: 5px;
            transition: background-color 0.3s, transform 0.3s;
        }

        nav button:hover,
        nav button.active {
            background-color: #3498db;
            transform: translateY(-2px);
        }

        main {
            padding: 20px;
            max-width: 1500px;
            margin: auto;
        }

        .cover-photo {
            width: 100%;
            height: 300px;
            overflow: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }

        .cover-photo img {
            width: 100%;
            height: auto;
            max-height: 300px;
            object-fit: cover;
            position: absolute;
            top: 0;
            left: 0;
            transition: transform 0.5s; /* Smooth transition for the movement */
        }

        .cover-photo img:hover {
            transform: scale(1.05); /* Scale up the image on hover */
            cursor: pointer; /* Change cursor to pointer to indicate interactivity */
        }

        .intro-container {
            display: flex;
            margin-top: 20px;
            
        }

        .additional-photo {
            flex: 1;
            height: 300px;
            overflow: hidden;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
        }

        .additional-photo img {
            width: 100%;
            height: auto;
            max-height: 300px;
            object-fit: cover;
            transition: transform 0.5s; /* Smooth transition for the movement */
        }

        .additional-photo img:hover {
            transform: scale(1.05); /* Scale up the image on hover */
            cursor: pointer; /* Change cursor to pointer to indicate interactivity */
        }

        .introduction {
            flex: 1;
            padding: 20px;
            background-color:#0d1319;
            border-radius: 8px;
            border: none;
            font-family: "Chewy", system-ui;
            font-weight: 400;
            color: rgb(219, 219, 219);
        }

    
        .more-button button {
            padding: 10px 20px;
            background-color: #27ae60;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }

        .more-button button:hover {
            background-color: #2ecc71;
        }

        footer {
            background-color: #2c3e50;
            color: #fff;
            padding: 20px;
            text-align: center;
            position: relative;
        }

        .footer-bottom {
            margin-top: 20px;
        }
        .introText {
            font-family: "Open Sans", sans-serif;
            font-size: 25px;
            letter-spacing: 1px;
        }
        .aboutUs {
             font-family: "Chewy", system-ui;
            font-weight: 400;
            color: rgb(219, 219, 219);
             letter-spacing: 2px;
        }
         .aboutText {
            font-family: "Open Sans", sans-serif;
            font-size: 25px;
            letter-spacing: 1px;
            color: rgb(219, 219, 219);
        }
          .sliderText {
            font-family: "Open Sans", sans-serif;
            font-size: 30px;
            color: rgb(242, 242, 242);
            letter-spacing: 1px;
        }

        h5 {
            font-size: 55px;
            font-family: "Chewy", system-ui;
            font-weight: 400;
            font-style: normal;
            color: rgb(242, 242, 242);
            letter-spacing: 2px;
        }

   
    
    </style>
</head>
<body>
    <header>
        <div class="logo">Larawang Munti</div>
        
       
       
       
       
        <nav>
               <button onclick="location.href='#aboutUs'" aria-label="About Us">About Us</button>
            <button onclick="location.href='Historical.html'" aria-label="Historical Landmarks">Historical Landmarks</button>
            <button onclick="location.href='bestlocation.html'" aria-label="Best Locations">Best Locations</button>
            <button onclick="location.href='logout.php'" aria-label="log out">Log out</button>
        </nav>
    </header>

    <main>
  
          <div class="carousel slide" id="carouselDemo" data-bs-wrap="true" data-bs-ride="carousel">

            <div class="carousel-inner">
                <div class="carousel-item active">
                    <img src="Museo.jpg" class="w-100">
                    <div class="carousel-caption">
                        <h5>Visit our new Museo de Muntinlupa</h5>
                        <p class="sliderText">Our first museum that contains hundreds of artifacts of the past</p>
                    </div>
                </div>
                <div class="carousel-item">
                    <img src="central park.jpg" class="w-100">
                    <div class="carousel-caption">
                        <h5>Go to our Central Park</h5>
                        <p class="sliderText">Do recreational activities with your family in our filinvest central park</p>
                    </div>
                </div>
                <div class="carousel-item">
                    <img src="BilibidP.jpg" class="w-100">
                    <div class="carousel-caption">
                        <h5>Explore historic places</h5>
                        <p class="sliderText">New Bilibid prison built since 1940</p>
                    </div>
                </div>
                <div class="carousel-item">
                    <img src="Jamboree-Lake.jpg" class="w-100">
                    <div class="carousel-caption">
                        <h5>Enjoy our preserved green spaces</h5>
                        <p class="sliderText">Visit the smallest lake in the Philippines</p>
                    </div>
               </div>
            </div>

            <button class="carousel-control-prev" type="button" data-bs-target="#carouselDemo" data-bs-slide="prev">
                <span class="carousel-control-prev-icon"></span>
            </button>

            <button class="carousel-control-next" type="button" data-bs-target="#carouselDemo" data-bs-slide="next">
                <span class="carousel-control-next-icon"></span>
            </button>
            <div class="carousel-indicators">
                <button type="button" class="active" data-bs-target="#carouselDemo" data-bs-slide-to="0"></button>
                <button type="button"data-bs-target="#carouselDemo" data-bs-slide-to="1"></button>
                <button type="button"data-bs-target="#carouselDemo" data-bs-slide-to="2"></button>
                <button type="button"data-bs-target="#carouselDemo" data-bs-slide-to="3"></button>
               
            </div>
        </div>

        <div class="intro-container">
            <section class="additional-photo">
                <img src="cityhall.jpg" alt="City Hall" loading="lazy">
            </section>

            <div class="introduction">             
         <p class="introText">Explore the city of Muntinlupa through images, showcasing its beauty, culture, and heritage. Muntinlupa
                officially the City of Muntinlupa, is a highly urbanized city in the 
                National Capital Region of the Philippines.
                According to the 2020 census, it has a population of 543,445 people.</p>

            </div>
        </div>
         <div class="intro-container">
            <div class="introduction">
                <h2>Visit churches of Muntinlupa</h2>
                <p class="introText">
                    Muntinlupa has alot of churches and one of them is the Diocesan Shrine of Our Lady of the Abandoned in Poblacion Muntinlupa.
                </p>
            </div>
                <section class="additional-photo">
                    <img src="Diocesan Shrine and Parish of Our Lady of the Abandoned - Muntinlupa City.jpg" loading="lazy">
                </section>
           
        </div>
        <div class="introduction">
            <h2>DID YOU KNOW?</h2>
            <p class="introText">
                Muntinlupa is on the top 10 richest cities based on their locally sourced revenue.
            </p>
        </div>
          <div id="aboutUs" class="about-content">
         
            <h2 class="aboutUs">About Us</h2>
            <p class="aboutText">Welcome to Larawang Munti! We are a <a href="folder 2/team 3.php">team</a> dedicated to showcasing the rich history and vibrant culture of Muntinlupa through its landmarks. Our goal is to provide a comprehensive guide for both residents and visitors to explore and appreciate the beauty and heritage of our city.</p>
            <p class="aboutText">Our website offers detailed information, stunning images, and insightful narratives about each landmark. We hope to inspire curiosity and foster a deeper connection with our local heritage.</p>
        </div>
    </main>

    <footer>
        <div class="footer-bottom">
            <p>&copy; 2024 Larawang Munti. All Rights Reserved.</p>
        </div>
    </footer>

   <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.min.js"></script>
   
</body>
</html>



