import React, { useEffect, useRef, useState, useContext } from "react";
import { Helmet } from "react-helmet";
import "../styles/tour-details.css";
import { Container, Row, Col, Form, ListGroup } from "reactstrap";
import { useParams } from "react-router-dom";
import calculateAvgRating from "./../utils/avgRating";
import avatar from "../assets/images/avatar.jpg";
import Booking from "../components/Booking/Booking";
import Newsletter from "../shared/Newsletter";
import useFetch from "../hooks/useFetch";
import { BASE_URL } from "../utils/config";
import { AuthContext } from "./../context/AuthContext";

const tourSeoMeta = {
  "FullDay Paracas and Huacachina": {
    title: "FullDay Paracas and Huacachina - Aventura y Naturaleza",
    description: "Explora Paracas e Ica en un día. Islas Ballestas, oasis de Huacachina, viñedos, historia y adrenalina en carros areneros desde Lima."
  },
  "Dune Buggy & Sandboard": {
    title: "Dune Buggy & Sandboard - Aventura en las dunas de Ica",
    description: "Disfruta de la emoción del sandboarding y un recorrido en buggy por las gigantescas dunas de Huacachina."
  },
  "Paracas National Reserve": {
    title: "Reserva Nacional de Paracas - Naturaleza y Cultura",
    description: "Conoce la biodiversidad marina y paisajes únicos del desierto costero peruano en esta reserva natural."
  },
  "Islas Ballestas": {
    title: "Islas Ballestas - Fauna Marina Peruana",
    description: "Navega a las Islas Ballestas para ver lobos marinos, pingüinos y aves exóticas en su hábitat natural."
  },
  "Private Tour": {
    title: "Private Tour - Experiencia Personalizada",
    description: "Vive una experiencia única y exclusiva con nuestros tours privados en Paracas, Ica o Nazca."
  },
  "Yacht Charter": {
    title: "Yacht Charter en Paracas - Lujo y Libertad",
    description: "Alquila un yate privado y navega por las aguas de Paracas con estilo, confort y privacidad total."
  },
  "Special Services": {
    title: "Special Services - Eventos y Servicios a Medida",
    description: "Ofrecemos tours corporativos, filmaciones, bodas y experiencias únicas personalizadas en el mar o desierto."
  },
  "Nazca Lines": {
    title: "Nazca Lines - Misterios del Desierto",
    description: "Vuela sobre las enigmáticas Líneas de Nazca y descubre uno de los mayores misterios de la antigüedad peruana."
  }
};
const TourDetail = () => {
  const { id } = useParams();
  const reviewMsgRef = useRef("");
  const [tourRating, setTourRating] = useState(null);
  const { user } = useContext(AuthContext);

  // fetch data from db
  const { data: tour, loading, error } = useFetch(`${BASE_URL}/tour/get/${id}`);

  // destructure properties from tour object
  const {
    photo,
    title,
    desc,
    informacion,
    price,
    pricingType,
    reviews,
    city,
    distance,
    maxGroupSize,
    address,
  } = tour;

  const { totalRating, avgRating } = calculateAvgRating(reviews);

  //  format date
  const options = { day: "numeric", month: "long", year: "numeric" };

  // Submit request to the server
  const submitHandler = async (e) => {
    e.preventDefault();
    const reviewText = reviewMsgRef.current.value;

    // call api
    try {
      if (!user || user === undefined || user === null) {
        alert("Please sign in");
        return;
      }

      const data = new FormData();
      data.append("reviewText", reviewText);
      data.append("rating", tourRating);
      data.append("idtour", id);
      data.append("iduser", user?.id);

      const res = await fetch(`${BASE_URL}/review/create/`, {
        method: "post",
        credentials: "include",
        body: data,
      });

      const result = await res.json();
      alert(result.message);
    } catch (err) {
      console.log(err.message);
      //alert("Ocurrió un error. Por favor, intenta nuevamente más tarde.");
    }
  };

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [tour]);

  const seo = tourSeoMeta[title] || {
    title: `${title} - Turismo en Paracas`,
    description: `Descubre el tour "${title}" en Paracas, lleno de naturaleza y aventura.`
  };

  return (
    <>
      <Helmet>
        <title>{seo.title}</title>
        <meta name="description" content={seo.description} />
      </Helmet>
      <section>
        <Container>
          {loading && <h4 className="text-center pt-5">Loading.......</h4>}
          {error && <h4 className="text-center pt-5">{error}</h4>}
          {!loading && !error && (
            <Row>
              <Col lg="8">
                <div className="tour__content">
                  <img src={BASE_URL + photo} alt="" />

                  <div className="tour__info">
                    <h2>{title}</h2>
                    <div className="d-flex align-align-items-center gap-5">
                      <span className="tour__rating d-flex align-items-center gap-1">
                        <i
                          className="ri-star-fill"
                          style={{ color: "var(--secondary-color)" }}
                        ></i>{" "}
                        {avgRating === 0 ? null : avgRating}
                        {totalRating === 0 ? (
                          "Not rated"
                        ) : (
                          <span>({reviews?.length})</span>
                        )}
                      </span>

                      <span>
                        <i className="ri-map-pin-user-fill"></i>
                        {address}
                      </span>
                    </div>

                    <div className="tour__extra-details">
                      <span>
                        <i className="ri-map-pin-2-line"></i> {city}
                      </span>
                      <span>
                        <i className="ri-money-dollar-circle-line"></i> ${price} {pricingType ? `/ ${pricingType}` : ""}
                      </span>
                      <span>
                        <i className="ri-map-pin-time-line"></i> {distance} k/m
                      </span>
                      <span>
                        <i className="ri-group-line"></i> {maxGroupSize} people
                      </span>
                    </div>
                    <h5>Description</h5>
                    <p>{desc}</p>
                    <div dangerouslySetInnerHTML={{ __html: informacion }} />
                    {/*RESERVA  PARACAS*/}
                    {/* <table>                       
                      <tr>                         
                        <td>Due to an exceptional biological diversity, generated by the Humboldt Current and coastal upwelling occurring year-round, this part of the Pacific ocean is one of the most productive and richest in the world. Also considered a wildlife refuge, this natural area are 224 species of birds, over 180 fish and 20 species of cetaceans. The reserve also offers historical and cultural wonders which are evident in 114 recorded archaeological sites and a testament of the successful interaction of the ancient inhabitants of Paracas with the sea. Paracas reserve has been declared a Ramsar Site under the Convention of Wetlands of International Importance in 1991. Our guided program to paracas national reserve start at 11:00am to explore some of the geological phenomena alone this remarkable stretch of peninsula, such as panoramic views and read, white sand beaches, lines by colorful, sedimentary rocks, blue and turquoise waters, cold pacific swells.                         
                        </td>                       
                      </tr>                     
                    </table>                     
                    <br/>                     
                    <table>                       
                      <tr>                         
                        <th>INCLUDE</th>                       
                      </tr>                       
                      <tr>                        
                        <td>• Pick up from your hotel in Paracas.</td>                       
                      </tr>                       
                      <tr>                         
                        <td>• Private transportation.</td>                       
                      </tr>                       
                      <tr>                         
                        <td>• Professional English guide</td>                       
                      </tr>                       
                      <tr>                         
                        <td>• Entrance fees.</td>                       
                      </tr>                    
                    </table>                     
                    <table>                       
                      <tr>                         
                        <th>NOT INCLUDE</th>                       
                      </tr>                       
                      <tr>                         
                        <td>• Extras & gratuities</td>                       
                      </tr>                       
                      <tr>                         
                        <td>• Accommodation in Pisco or Paracas.</td>                       
                      </tr>                     
                    </table>                     
                    <table>                       
                      <tr>                         
                        <th>DURATION 3 hours (aprox)</th>                       
                      </tr>                      
                      <tr>                         
                        <td>• Departs every day from 9:00 a.m. to 14:00 p.m.</td>                       
                      </tr>                       
                      <tr>                         
                        <td>• A minimum of 2 participants are required.</td>                       
                      </tr>                     
                    </table> */}
                    {/* <table>                       
                      <tr>                         
                        <td>We meet at our office and escort you to Paracas dock. This two-hour round-trip tour of Peru's most famous islands lets you enjoy magnificent rocks formations sculpted by nature and is home of Humboldt penguins, south Americans sea lions and a multitude of marine birds. Services also available in First and Private classes.All yacht tours include a trained, certified, registered yatchsman and crewman/guide onboard. Our yacht services are insured and registered with all appropriate agencies as mandated by law.                         
                        </td>                       
                      </tr>                     
                    </table>                     
                    <table>                       
                      <tr>                         
                        <th>INCLUDE</th>                       
                      </tr>                                            
                      <tr>                         
                        <td>• Transfer to Paracas dock</td>                       
                      </tr>
                      <tr>                         
                        <td>• <b>Reserve and dock entrance fees pre-paid (over $6 US)</b></td>                       
                      </tr>                        
                      <tr>                         
                        <td>• Boat transport</td>                       
                      </tr>                       
                      <tr>                         
                        <td>• Backup boat primed & ready</td>                       
                      </tr>                       
                      <tr>                         
                        <td>• Professional Yachtsman and mate</td>                       
                      </tr>                       
                      <tr>                         
                        <td>• English speaking guide</td>                       
                      </tr>                       
                                          
                    </table>                     
                    <table>                       
                      <tr>                         
                        <th>NOT INCLUDE</th>                       
                      </tr>                       
                      <tr>                         
                        <td>• Extras & gratuities</td>                       
                      </tr>                       
                      <tr>                         
                        <td>• Accommodation</td>                       
                      </tr>                     
                    </table>                     
                    <table>                       
                      <tr>                         
                        <th>DURATION 2 hours</th>                       
                      </tr>                       
                      <tr>                         
                        <td>Departs daily: 8:00 am, 9:00 am, 10:am</td>                       
                      </tr>                    
                    </table> */}
                  </div>
                  {/* =========== tour reviews section ==============*/}
                  <div className="tour__reviews mt-4">
                    <h4>Reviews ({reviews?.length} reviews)</h4>
                    <Form onSubmit={submitHandler}>
                      <div className="d-flex align-items-center gap-3 mb-4 rating__group">
                        <span onClick={() => setTourRating(1)}>
                          1 <i className="ri-star-s-fill"></i>
                        </span>
                        <span onClick={() => setTourRating(2)}>
                          2 <i className="ri-star-s-fill"></i>
                        </span>
                        <span onClick={() => setTourRating(3)}>
                          3 <i className="ri-star-s-fill"></i>
                        </span>
                        <span onClick={() => setTourRating(4)}>
                          4 <i className="ri-star-s-fill"></i>
                        </span>
                        <span onClick={() => setTourRating(5)}>
                          5 <i className="ri-star-s-fill"></i>
                        </span>
                      </div>

                      <div className="review__input">
                        <input
                          type="text"
                          ref={reviewMsgRef}
                          placeholder="share your thoughts"
                          required
                        />
                        <button
                          className="btn primary__btn text-white"
                          type="submit"
                        >
                          Submit
                        </button>
                      </div>
                    </Form>

                    <ListGroup className="user__reviews">
                      {reviews > 0 ? (
                        <h4 className="text-center">No reviews found</h4>
                      ) : (
                        reviews?.map((review) => (
                          <div className="review__item" key={review.id}>
                            <img src={avatar} alt="" />

                            <div className="w-100">
                              <div className="d-flex align-items-center justify-content-between">
                                <div>
                                  <h5>{review.username}</h5>
                                  <p>
                                    {new Date(
                                      review.createdAt
                                    ).toLocaleDateString("en-US", options)}
                                  </p>
                                </div>
                                <span className="d-flex align-items-center">
                                  {review.rating}
                                  <i className="ri-star-s-fill"></i>
                                </span>
                              </div>
                              <h6>{review.reviewText}</h6>
                            </div>
                          </div>
                        ))
                      )}
                    </ListGroup>
                  </div>
                  {/* =========== tour reviews section end ==============*/}
                </div>
              </Col>

              <Col lg="4">
                <Booking tour={tour} avgRating={avgRating} />
              </Col>
            </Row>
          )}
        </Container>
      </section>
      <Newsletter />
    </>
  );
};

export default TourDetail;
