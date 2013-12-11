/**
 * 
 * Stores metadata for a  feed channel
 * 
 */
Tracking = {};
Tracking.entityName = 'channel_pod_tracking';
Tracking.entitySchema = {
    id: {
        type: String,
        renderable: false,
        writable: false
    },
    owner_id : {
        type: String,
        renderable: false,
        writable: false
    },    
    created : {
        type: String,
        renderable: true,
        writable: false
    },
    
    // last append time
    last_poll : {
        type : String,
        renderable : true,
        writable : false
    },  
  
    channel_id : {
        type : String,
        renderable : true,
        writable : false
    }  
};

Tracking.compoundKeyContraints = {
    channel_id : 1,
    owner_id : 1
};

module.exports = Tracking;