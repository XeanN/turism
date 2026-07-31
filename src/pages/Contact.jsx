import React from "react";
import { Helmet } from "react-helmet";
import CommonSection from "../shared/CommonSection";
import "../styles/contact.css";
import emailjs from "@emailjs/browser";
import { useLanguage } from "../context/LanguageContext";

const pageText = {
  en: {
    metaTitle: "Contact Us | Turismo Nautico Paracas",
    metaDescription: "Contact us to book your tour in Paracas. Office at Paracas Bay, support via WhatsApp and email. We help you build your ideal itinerary.",
    heroTitle: "Contact Us, We’re here to Help! Our Team Would Love to Answer Your Questions",
    howCanWeHelp: "How Can We Help? Contact us!",
    intro: (
      <>
        Whether you have a question about a destination, tour, trek, package, or even if you want to create an itinerary from scratch, our team is ready to answer all your questions about{" "}
        <strong>the southern coastal side of Peru.</strong>
      </>
    ),
    name: "Full Name*",
    email: "Email*",
    subject: "Subject*",
    message: "Message*",
    submit: "SUBMIT NOW",
    location: "Location",
    paracasOffice: "Paracas Office:",
    emergency: "Emergency:",
    whatsapp: "Whatsapp:",
    agencyType: "Travel Agency & Tour Operator",
    address: 'Inside Marina Turística "Tourist Pier", right next to Hotel San Agustín - Paracas. Open 7:30 am to 1:00 pm (Paracas)',
    sentOk: "Your message was sent successfully ✅",
    sentError: "There was an error sending your message ❌",
  },
  es: {
    metaTitle: "Contáctanos | Turismo Nautico Paracas",
    metaDescription: "Contáctanos para reservar tu tour en Paracas. Oficina en Bahía de Paracas, atención por WhatsApp y correo. Te ayudamos a armar tu itinerario ideal.",
    heroTitle: "Contáctanos, Estamos Aquí para Ayudarte. Nuestro Equipo Quiere Responder Todas tus Preguntas",
    howCanWeHelp: "¿Cómo Podemos Ayudarte? ¡Contáctanos!",
    intro: (
      <>
        Ya sea que tengas una pregunta sobre un destino, tour, caminata, paquete, o incluso si quieres armar un itinerario desde cero, nuestro equipo está listo para responder todas tus preguntas sobre{" "}
        <strong>la costa sur del Perú.</strong>
      </>
    ),
    name: "Nombre Completo*",
    email: "Correo*",
    subject: "Asunto*",
    message: "Mensaje*",
    submit: "ENVIAR AHORA",
    location: "Ubicación",
    paracasOffice: "Oficina Paracas:",
    emergency: "Emergencia:",
    whatsapp: "Whatsapp:",
    agencyType: "Agencia de Viajes y Operador de Tours",
    address: 'Dentro de la Marina Turística "Muelle Turístico", al lado del Hotel San Agustín - Paracas. Abierto de 7:30 am a 1:00 pm (Paracas)',
    sentOk: "Tu mensaje fue enviado correctamente ✅",
    sentError: "Ocurrió un error al enviar el mensaje ❌",
  },
};

const Contact = () => {
  const lang = useLanguage();
  const t = pageText[lang];
  const canonicalUrl = lang === "es"
    ? "https://turismonauticoparacas.com/es/contact"
    : "https://turismonauticoparacas.com/contact";

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
          alert(t.sentOk);
          form.reset();
        },
        (error) => {
          console.log("Error al enviar:", error.text);
          alert(t.sentError);
        }
      );

    const whatsappText = `📩 *Contact Form*\n\n👤 *Nombre:* ${fullName}\n📧 *Email:* ${email}\n📌 *Asunto:* ${subject}\n📝 *Mensaje:* ${message}`;
    const phone = "51956481002";
    const url = `https://wa.me/${phone}?text=${encodeURIComponent(whatsappText)}`;
    window.open(url, "_blank");
    form.reset();
  };

  return (
    <>
      <Helmet>
        <title>{t.metaTitle}</title>
        <meta name="description" content={t.metaDescription} />
        <link rel="canonical" href={canonicalUrl} />
        <link rel="alternate" hrefLang="en" href="https://turismonauticoparacas.com/contact" />
        <link rel="alternate" hrefLang="es" href="https://turismonauticoparacas.com/es/contact" />
        <link rel="alternate" hrefLang="x-default" href="https://turismonauticoparacas.com/contact" />
        <meta property="og:title" content={t.metaTitle} />
        <meta property="og:description" content={t.metaDescription} />
        <meta property="og:type" content="website" />
        <meta property="og:url" content={canonicalUrl} />
      </Helmet>
      <CommonSection title={t.heroTitle} />
      <section className="contact">
        <div className="container contact-container">
          <div className="contact-info">
            <h2>{t.howCanWeHelp}</h2>
            <p>{t.intro}</p>

            <form className="contact-form" onSubmit={handleSubmit}>
              {/* Honeypot escondido */}
              <div style={{ display: "none" }}>
                <label htmlFor="company">Do not fill this field</label>
                <input type="text" name="company" id="company" autoComplete="off" />
              </div>

              <input type="text" name="name" placeholder={t.name} required />
              <input type="email" name="email" placeholder={t.email} required />
              <input type="text" name="title" placeholder={t.subject} required />
              <textarea name="message" placeholder={t.message} rows="5" required></textarea>

              <div className="recaptcha-box">
                {/* reCAPTCHA desactivado */}
                {/* <p>[reCAPTCHA]</p> */}
              </div>

              <button type="submit" className="submit-btn">{t.submit}</button>
            </form>
          </div>

          <div className="contact-details">
            <h3>{t.location}</h3>
            <p>A.H.Alberto Tataje Muñoz Mz "C" Lote 2, Paracas, Peru</p>

            <ul>
              <li><strong>{t.paracasOffice}</strong> +51 947-058-508</li>
              <li><strong>{t.emergency}</strong> +51 937-154-395</li>
              <li><strong>{t.whatsapp}</strong> +51 956-481-002</li>
            </ul>

            <h3>Turismo Nautico Paracas</h3>

            <ul>
              <li><strong>{t.agencyType}</strong></li>
              <li>Amarilis Pereda & Lucio Hancco</li>
              <li>{t.address}</li>
            </ul>
          </div>
        </div>
      </section>
    </>
  );
};

export default Contact;
