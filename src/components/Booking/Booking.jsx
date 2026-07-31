import React, { useState } from "react";
//import React, { useState, useContext } from "react";
import "./booking.css";
import { Form, FormGroup, ListGroup, ListGroupItem, Button } from "reactstrap";

//import { useNavigate } from "react-router-dom";
//import { AuthContext } from "../../context/AuthContext";
import { BASE_URL } from "../../utils/config";
import { useLanguage } from "../../context/LanguageContext";

const text = {
  en: {
    information: "Information",
    fullName: "Full Name",
    phone: "Phone",
    guests: "Guest",
    total: "Total",
    reserveNow: "Reserve Now",
    whatsappMessage: (booking) =>
      `Hi! I am interested in booking the tour. My name is ${booking.fullName}, my phone is ${booking.phone} and I want to book ${booking.guestSize} guest(s).`,
  },
  es: {
    information: "Información",
    fullName: "Nombre Completo",
    phone: "Teléfono",
    guests: "Personas",
    total: "Total",
    reserveNow: "Reservar Ahora",
    whatsappMessage: (booking) =>
      `¡Hola! Estoy interesado/a en reservar el tour. Mi nombre es ${booking.fullName}, mi teléfono es ${booking.phone} y quiero reservar para ${booking.guestSize} persona(s).`,
  },
};

const Booking = ({ tour, avgRating }) => {
  const lang = useLanguage();
  const t = text[lang];
  const { id, price, reviews, pricingType } = tour;
  //const navigate = useNavigate();

  //const { user } = useContext(AuthContext);

  const [booking, setBooking] = useState({
    idtour: id,
    informacion: "",
    fullName: "",
    phone: "",
    guestSize: 1,
    bookAt: "",

  });

  const handleChange = (e) => {
    setBooking((prev) => ({ ...prev, [e.target.id]: e.target.value }));
  };

  // const serviceFee = 10;
  const serviceFee = 0;
  const totalAmount =
    Number(price) * Number(booking.guestSize) + Number(serviceFee);

  //send data to the server
  const handleClick = async (e) => {
    e.preventDefault();

    try {
      

      const data = new FormData();
      data.append("idtour", booking.idtour);
      data.append("informacion", booking.informacion);
      data.append("email", booking.email);
      data.append("fullName", booking.fullName);
      data.append("phone", booking.phone);
      data.append("guestSize", booking.guestSize);
      data.append("bookAt", booking.bookAt);

      const res = await fetch(`${BASE_URL}/booking/create`, {
        method: "post",
        credentials: "include",
        body: data,
      });

      const result = await res.json();

      if (result.success) {
        //const tourName = result.tourName;
        const whatsappMessage = t.whatsappMessage(booking);
        const encodedMessage = encodeURIComponent(whatsappMessage);
        window.location.href = `https://wa.me/+51940578027/?text=${encodedMessage}`;
      } else {
        return alert(result.message);
      }
    } catch (err) {
      alert(err.message);
    }
  };

  return (
    <div className="booking">
      <div className="booking__top d-flex align-items-center justify-content-between">
        <h3>
          ${price} <span>/{pricingType}</span>
        </h3>
        <span className="tour__rating d-flex align-items-center">
          <i className="ri-star-fill"></i>
          {avgRating === 0 ? null : avgRating} {reviews?.length}
        </span>
      </div>

      {/* =============== booking form start ================== */}
      <div className="booking__form">
        <h5>{t.information}</h5>
        <p></p>
        <Form className="booking__info-form" onSubmit={handleClick}>
          <FormGroup>
            <input
              type="text"
              placeholder={t.fullName}
              id="fullName"
              required
              onChange={handleChange}
            />
          </FormGroup>
          <FormGroup>
            <input
              type="number"
              placeholder={t.phone}
              id="phone"
              required
              onChange={handleChange}
            />
          </FormGroup>
          <FormGroup className="d-flex align-items-center gap-3">
            <input
              type="date"
              placeholder=""
              id="bookAt"
              required
              onChange={handleChange}
            />
            <input
              type="number"
              placeholder={t.guests}
              id="guestSize"
              required
              onChange={handleChange}
            />
          </FormGroup>
        </Form>
      </div>
      {/* =============== booking form end ================== */}

      {/* =============== booking bottom start ================== */}
      <div className="booking__bottom">
        <ListGroup>
          <ListGroupItem className="border-0 px-0">
            <h5 className="d-flex align-items-center gap-1">
              ${price} <i className="ri-close-line"></i> 1 {pricingType}
            </h5>
            <span> ${price}</span>
          </ListGroupItem>
          {/* <ListGroupItem className="border-0 px-0">
            <h5>Service charge</h5>
            <span> ${serviceFee}</span>
          </ListGroupItem> */}
          <ListGroupItem className="border-0 px-0 total">
            <h5>{t.total}</h5>
            <span> ${totalAmount}</span>
          </ListGroupItem>
        </ListGroup>

        <Button className="btn primary__btn w-100 mt-4" onClick={handleClick}>
          {t.reserveNow}
        </Button>
      </div>
      {/* =============== booking bottom end ================== */}
    </div>
  );
};

export default Booking;
