
import React, { useState } from "react";
import { Helmet } from "react-helmet";
import Lightbox from "yet-another-react-lightbox";
import "yet-another-react-lightbox/styles.css";
import CommonSection from "../shared/CommonSection";
import "../styles/gallery.css";
import { useLanguage } from "../context/LanguageContext";

const text = {
  en: {
    metaTitle: "Photo Gallery | Turismo Nautico Paracas",
    metaDescription: "Check out the best photos of our tours in Paracas: Ballestas Islands, Huacachina dunes, yachts and clients enjoying the southern coast of Peru.",
    pageTitle: "Our best moments",
    imageAlt: "Photo of tour in Paracas",
  },
  es: {
    metaTitle: "Galería de Fotos | Turismo Nautico Paracas",
    metaDescription: "Mira las mejores fotos de nuestros tours en Paracas: Islas Ballestas, dunas de Huacachina, yates y clientes disfrutando la costa sur del Perú.",
    pageTitle: "Nuestros Mejores Momentos",
    imageAlt: "Foto de tour en Paracas",
  },
};

const Gallery = () => {
  const lang = useLanguage();
  const t = text[lang];
  const canonicalUrl = lang === "es"
    ? "https://turismonauticoparacas.com/es/gallery"
    : "https://turismonauticoparacas.com/gallery";
  const [open, setOpen] = useState(false);
  const [index, setIndex] = useState(0);
//aca aumentamos la cantidad de imagenes
  const images = Array.from({ length: 52 }, (_, i) => ({
    src: `/images/gallery${i + 1}.jpeg`,
  }));

  return (
    <>
      <Helmet>
        <title>{t.metaTitle}</title>
        <meta name="description" content={t.metaDescription} />
        <link rel="canonical" href={canonicalUrl} />
        <link rel="alternate" hrefLang="en" href="https://turismonauticoparacas.com/gallery" />
        <link rel="alternate" hrefLang="es" href="https://turismonauticoparacas.com/es/gallery" />
        <link rel="alternate" hrefLang="x-default" href="https://turismonauticoparacas.com/gallery" />
        <meta property="og:title" content={t.metaTitle} />
        <meta property="og:type" content="website" />
        <meta property="og:url" content={canonicalUrl} />
      </Helmet>
      <CommonSection title={t.pageTitle} />
      <section className="gallery">
        <div className="container gallery-grid">
          {images.map((img, i) => (
            <img
              key={i}
              src={img.src}
              alt={`${t.imageAlt} ${i + 1}`}
              className="thumbnail"
              onClick={() => {
                setIndex(i);
                setOpen(true);
              }}
            />
          ))}
        </div>

        <Lightbox open={open} close={() => setOpen(false)} slides={images} index={index} />
      </section>
    </>
  );
};

export default Gallery;
