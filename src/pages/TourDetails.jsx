// src/pages/TourDetail.jsx
import React, { useEffect, useState, useContext, useRef } from "react";
import useFetch from "../hooks/useFetch";
import { BASE_URL, IMAGE_BASE_URL } from "../utils/config";
import {
  Container, Row, Col, Form, ListGroup
} from "reactstrap";
import { useParams } from "react-router-dom";
import calculateAvgRating from "../utils/avgRating";
import Booking from "../components/Booking/Booking";
import avatar from "../assets/images/avatar.jpg";
import Newsletter from "../shared/Newsletter";
import { AuthContext } from "../context/AuthContext";

const TourDetail = () => {
  const { id } = useParams();
  const { user } = useContext(AuthContext);
  const reviewRef = useRef();
  const [tourRating, setTourRating] = useState(0);

  const { data: tourArr, loading, error } = useFetch(`${BASE_URL}/get&id=${id}`);
  const tour = tourArr[0] || {};

  const {
    photo, title, desc, price, reviews = [],
    city, distance, maxGroupSize, address
  } = tour;

  const { totalRating, avgRating } = calculateAvgRating(reviews);
  const imageUrl = `${IMAGE_BASE_URL}${photo?.replace('/public', '')}`;

  useEffect(() => { window.scrollTo(0, 0); }, [id]);

  const submitHandler = async (e) => {
    e.preventDefault();
    if (!user) return alert("Please sign in");

    try {
      const res = await fetch(`${BASE_URL}/review&id=${id}`, {
        method: "post",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          username: user.username,
          reviewText: reviewRef.current.value,
          rating: tourRating
        })
      });
      const result = await res.json();
      alert(result.message);
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) return <h4 className="text-center">Loading...</h4>;
  if (error)   return <h4 className="text-center">{error}</h4>;

  return (
    <>
      <Container className="py-5">
        <Row>
          <Col lg="8">
            <img src={imageUrl} alt={title} className="w-100" />
            <h2 className="my-3">{title}</h2>
            <div className="d-flex gap-3 mb-3">
              <span><i className="ri-star-fill"></i> {avgRating || "Not rated"}</span>
              <span><i className="ri-map-pin-user-fill"></i> {address}</span>
            </div>
            <p>{desc}</p>
            <h4>Details</h4>
            <ul>
              <li><i className="ri-map-pin-2-line"></i> {city}</li>
              <li><i className="ri-money-dollar-circle-line"></i> ${price} per person</li>
              <li><i className="ri-map-pin-time-line"></i> {distance} km</li>
              <li><i className="ri-group-line"></i> {maxGroupSize} people</li>
            </ul>

            <Form onSubmit={submitHandler} className="mt-4">
              <div className="d-flex gap-3 mb-3">
                {[1,2,3,4,5].map(n => (
                  <span key={n} onClick={() => setTourRating(n)}>
                    {n} <i className="ri-star-s-fill"></i>
                  </span>
                ))}
              </div>
              <input ref={reviewRef} type="text" required placeholder="Share your thoughts" />
              <button className="btn primary__btn mt-2" type="submit">Submit</button>
            </Form>

            <ListGroup className="mt-4">
              {reviews.map(r => (
                <div key={r.id} className="d-flex my-3">
                  <img src={avatar} alt="avatar" className="rounded-circle" width="50" />
                  <div className="ms-3">
                    <div className="d-flex justify-content-between">
                      <strong>{r.username}</strong>
                      <span>{r.rating} <i className="ri-star-s-fill"></i></span>
                    </div>
                    <p>{r.reviewText}</p>
                  </div>
                </div>
              ))}
            </ListGroup>
          </Col>

          <Col lg="4">
            <Booking tour={tour} avgRating={avgRating} />
          </Col>
        </Row>
      </Container>
      <Newsletter />
    </>
  );
};

export default TourDetail;
