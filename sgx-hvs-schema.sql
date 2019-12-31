--
-- PostgreSQL database dump
--

-- Dumped from database version 9.4.25
-- Dumped by pg_dump version 11.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: host_credentials; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.host_credentials (
    id text NOT NULL,
    host_id text NOT NULL,
    hardware_uuid text,
    host_name text,
    credential text NOT NULL,
    created_at timestamp with time zone
);


ALTER TABLE public.host_credentials OWNER TO dbuser;

--
-- Name: host_statuses; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.host_statuses (
    id text NOT NULL,
    host_id text NOT NULL,
    status text,
    host_report text NOT NULL,
    created_time timestamp with time zone
);


ALTER TABLE public.host_statuses OWNER TO dbuser;

--
-- Name: hosts; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.hosts (
    id text NOT NULL,
    name text NOT NULL,
    description text,
    connection_string text NOT NULL,
    hardware_uuid text
);


ALTER TABLE public.hosts OWNER TO dbuser;

--
-- Name: reports; Type: TABLE; Schema: public; Owner: dbuser
--

CREATE TABLE public.reports (
    id text NOT NULL,
    host_id text NOT NULL,
    trust_report text NOT NULL,
    created_time timestamp with time zone,
    expiration_time timestamp with time zone,
    saml text
);


ALTER TABLE public.reports OWNER TO dbuser;

--
-- Name: host_credentials host_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.host_credentials
    ADD CONSTRAINT host_credentials_pkey PRIMARY KEY (id);


--
-- Name: host_statuses host_statuses_pkey; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.host_statuses
    ADD CONSTRAINT host_statuses_pkey PRIMARY KEY (id);


--
-- Name: hosts hosts_pkey; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.hosts
    ADD CONSTRAINT hosts_pkey PRIMARY KEY (id);


--
-- Name: reports reports_pkey; Type: CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_pkey PRIMARY KEY (id);


--
-- Name: host_credentials host_credentials_host_id_hosts_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.host_credentials
    ADD CONSTRAINT host_credentials_host_id_hosts_id_foreign FOREIGN KEY (host_id) REFERENCES public.hosts(id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: host_statuses host_statuses_host_id_hosts_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.host_statuses
    ADD CONSTRAINT host_statuses_host_id_hosts_id_foreign FOREIGN KEY (host_id) REFERENCES public.hosts(id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: reports reports_host_id_hosts_id_foreign; Type: FK CONSTRAINT; Schema: public; Owner: dbuser
--

ALTER TABLE ONLY public.reports
    ADD CONSTRAINT reports_host_id_hosts_id_foreign FOREIGN KEY (host_id) REFERENCES public.hosts(id) ON UPDATE RESTRICT ON DELETE RESTRICT;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

