"""Страна -> регион. Данные статичные, без внешних сервисов."""
EUROPE = set("DE NL FI SE FR PL CZ AT CH GB IE ES IT PT BE DK NO LU EE LV LT RO BG HU SK SI HR GR UA MD RS IS CY MT AL BA MK ME".split())
ASIA = set("JP KR SG HK TW CN IN ID MY TH VN PH AE IL TR KZ GE AM AZ UZ KG MN BD PK LK NP KH LA".split())
AMERICA = set("US CA BR MX AR CL CO PE UY VE EC CR PA".split())


def region_of(cc: str) -> str:
    cc = (cc or "").upper()
    if cc == "RU":
        return "russia"
    if cc in EUROPE:
        return "europe"
    if cc in ASIA:
        return "asia"
    if cc in AMERICA:
        return "america"
    return "other"
