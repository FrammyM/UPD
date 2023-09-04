#!/usr/bin/env python
# coding: utf-8

# In[1]:


import rsa

(pubkey, privkey) = rsa.newkeys(1024)

pub = pubkey.save_pkcs1()
pubfile = open('public.pem','wb')
pubfile.write(pub)
pubfile.close()
 
pri = privkey.save_pkcs1()
prifile = open('private.pem','wb')
prifile.write(pri)
prifile.close()


# In[ ]:





# In[ ]:





# In[ ]:




