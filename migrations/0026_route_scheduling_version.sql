-- Use the identity sequence as a durable scheduling revision as well as an
-- insertion identity. A trigger covers every writer, including account deletion.
CREATE FUNCTION gateway_route_scheduling_revision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- Metadata and availability do not define the weighted schedule. The
    -- selector independently reconciles its scores with the ready set.
    -- Older entries omit weight, which has the same effective value as 1.
    IF NEW.strategy IS DISTINCT FROM OLD.strategy OR (
        NEW.entries IS DISTINCT FROM OLD.entries AND
        CASE
            -- Malformed entries cannot be compared as schedules; invalidate
            -- conservatively, including when a PUT repairs an older row.
            WHEN jsonb_typeof(NEW.entries) IS DISTINCT FROM 'array'
              OR jsonb_typeof(OLD.entries) IS DISTINCT FROM 'array' THEN TRUE
            ELSE
                (SELECT jsonb_agg(jsonb_build_array(entry->'key_id', entry->'model',
                                                  COALESCE(entry->'weight', '1'::jsonb)) ORDER BY ordinal)
                 FROM jsonb_array_elements(NEW.entries) WITH ORDINALITY AS e(entry, ordinal))
                IS DISTINCT FROM
                (SELECT jsonb_agg(jsonb_build_array(entry->'key_id', entry->'model',
                                                  COALESCE(entry->'weight', '1'::jsonb)) ORDER BY ordinal)
                 FROM jsonb_array_elements(OLD.entries) WITH ORDINALITY AS e(entry, ordinal))
        END
    ) THEN
        NEW.incarnation := nextval(pg_get_serial_sequence(TG_RELID::regclass::text, 'incarnation'));
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER gateway_route_scheduling_revision
BEFORE UPDATE ON gateway_routes
FOR EACH ROW EXECUTE FUNCTION gateway_route_scheduling_revision();
