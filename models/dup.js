Dup = {
  entityName : 'dup',
  entitySchema : {
    owner_id : {
      type: String,
      renderable: false,
      writable: false
    },

    channel_id : {
      type : String,
      renderable : true,
      writable : false
    },

    bip_id : {
      type : String,
      renderable : true,
      writable : false
    },

    created : {
      type: Number,
      renderable: true,
      writable: false
    },

    // last append time
    last_update : {
      type : Number,
      renderable : true,
      writable : false
    },

    value : {
      type : String,
      renderable : true,
      writable : false
    }
  },
  compoundKeyContraints : {
    channel_id : 1,
    owner_id :1,
    bip_id :1,
    value : 1
  }
};

module.exports = Dup;