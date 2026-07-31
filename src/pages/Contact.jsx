import React from "react";
import { Helmet } from "react-helmet";
import CommonSection from "../shared/CommonSection";
import "../styles/contact.css";
import emailjs from "@emailjs/browser";

const Contact = () => {
  const handleSubmit = (e) => {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    const honeypot = formData.get("company"); // Honeypot
    if (honeypot) {
      console.log("Bot detectado, formulario bloqueado.");
      return;
    }

    const fullName = formData.get("name");
    const email = formData.get("email");
    const subject = formData.get("title");
    const message = formData.get("message");

    emailjs
      .sendForm(
        "service_vbzfuuu",
        "template_3d5iovd",
        form,
        "4zsaDURdbgabCbDU0"
      )
      .then(
        (result) => {
          console.log("Correo enviado:", result.text);
          alert("Tu mensaje fue enviado correctamente ✅");
          form.reset();
        },
        (error) => {
          console.log("Error al enviar:", error.text);
          alert("Ocurrió un error al enviar el mensaje ❌");
        }
      );

    const text = `📩 *Contact Form*\n\n👤 *Nombre:* ${fullName}\n📧 *Email:* ${email}\n📌 *Asunto:* ${subject}\n📝 *Mensaje:* ${message}`;
    const phone = "51956481002";
    const url = `https://wa.me/${phone}?text=${encodeURIComponent(text)}`;
    window.open(url, "_blank");
    form.reset();
  };

  return (
    <>
      <Helmet>
        <title>Contáctanos | Turismo Nautico Paracas</title>
        <meta
          name="description"
          content="Contáctanos para reservar tu tour en Paracas. Oficina en Bahía de Paracas, atención por WhatsApp y correo. Te ayudamos a armar tu itinerario ideal."
        />
        <link rel="canonical" href="https://turismonauticoparacas.com/contact" />
        <meta property="og:title" content="Contáctanos - Turismo Nautico Paracas" />
        <meta
          property="og:description"
          content="Escríbenos para reservar tu tour en Paracas: Islas Ballestas, Reserva Nacional, Nazca y más."
        />
        <meta property="og:type" content="website" />
        <meta property="og:url" content="https://turismonauticoparacas.com/contact" />
      </Helmet>
      <CommonSection title="Contact Us, We’re here to Help! Our Team Would Love to Answer Your Questions" />
      <section className="contact">
        <div className="container contact-container">
          <div className="contact-info">
            <h2>How Can We Help? Contact us!</h2>
            <p>
              Whether you have a question about a destination, tour, trek, package, or even if you want to create an itinerary from scratch, our team is ready to answer all your questions about{" "}
              <strong>the southern coastal side of Peru.</strong>
            </p>

            <form className="contact-form" onSubmit={handleSubmit}>
              {/* Honeypot escondido */}
              <div style={{ display: "none" }}>
                <label htmlFor="company">Do not fill this field</label>
                <input type="text" name="company" id="company" autoComplete="off" />
              </div>

              <input type="text" name="name" placeholder="Full Name*" required />
              <input type="email" name="email" placeholder="Email*" required />
              <input type="text" name="title" placeholder="Subject*" required />
              <textarea name="message" placeholder="Message*" rows="5" required></textarea>

              <div className="recaptcha-box">
                {/* reCAPTCHA desactivado */}
                {/* <p>[reCAPTCHA]</p> */}
              </div>

              <button type="submit" className="submit-btn">SUBMIT NOW</button>
            </form>
          </div>

          <div className="contact-details">
            <h3>Location</h3>
            <p>A.H.Alberto Tataje Muñoz Mz "C" Lote 2, Paracas, Peru</p>

            <ul>
              <li><strong>Paracas Office:</strong> +51 947-058-508</li>
              <li><strong>Emergency:</strong> +51 937-154-395</li>
              <li><strong>Whatsapp:</strong> +51 956-481-002</li>
            </ul>

            <h3>Turismo Nautico Paracas</h3>

            <ul>
              <li><strong>Travel Agency & Tour Operator</strong></li>
              <li>Amarilis Pereda & Lucio Hancco</li>
              <li>Inside Marina Turística "Tourist Pier", right next to Hotel San Agustín - Paracas. Open 7:30 am to 1:00 pm (Paracas)</li>
            </ul>
          </div>
        </div>
      </section>
    </>
  );
};

export default Contact;
